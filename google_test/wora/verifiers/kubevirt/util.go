package kubevirt

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cilium/cilium/pkg/time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	networkclientset "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	"k8s.io/kubectl/pkg/scheme"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog"
	gvmv1 "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/kubevm/vm-controller/api/v1"
	vmruntimev1 "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/kubevm/vm-runtime-operator/api/v1"
	"kubevirt.io/client-go/kubecli"
	cdiv1beta1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
)

// networkIP holds IPs to corresponding network names.
type networkIP map[string]string

// networkConnection holds networks and default network which the workload connects to.
type networkConnection struct {
	networkIPs     networkIP
	defaultNetwork string
}

// createRESTClient takes a kubeconfig and returns a REST client to perform
// CRUD operations of vmruntime, virtualmachinedisk and virtualmachine.
func createRESTClient(config *rest.Config) (*rest.RESTClient, error) {
	err := vmruntimev1.AddToScheme(scheme.Scheme)
	if err != nil {
		return nil, err
	}
	err = gvmv1.AddToScheme(scheme.Scheme)
	if err != nil {
		return nil, err
	}

	config.GroupVersion = &vmruntimev1.GroupVersion
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	restClient, err := rest.UnversionedRESTClientFor(config)
	if err != nil {
		return nil, err
	}
	return restClient, nil
}

// createNetworkClient takes a kubeconfig and returns a client to interact with
// the network object.
func createNetworkClient(config *rest.Config) (*networkclientset.Clientset, error) {
	networkClient, err := networkclientset.NewForConfig(config)
	if err != nil {
		clientErr := fmt.Errorf("Failed to create config for test cluster network client: %v", err)
		return nil, clientErr
	}
	klog.Info("New network client created.")
	return networkClient, nil
}

func prettyPrint(obj any) string {
	s, _ := json.MarshalIndent(obj, "", "\t")
	return string(s)
}

// waitForVMRuntimePreflightcheckSuccess checks on the status of VMRuntime's
// preflight check status by the given polling interval up to the given maximum time ,
// will return context timeout error if VMRuntimeFlightcheck failed to become
// success.
func waitForVMRuntimePreflightcheckSuccess(ctx context.Context, client *rest.RESTClient, interval, timeout time.Duration) error {
	condition := func(ctx context.Context) (bool, error) {
		result := vmruntimev1.VMRuntime{}
		err := client.Get().Resource("vmruntimes").Name("vmruntime").Do(ctx).Into(&result)
		if err != nil {
			return false, err
		}
		if result.Status.PreflightCheckSummary.PreflightCheckPassed == nil || !*result.Status.PreflightCheckSummary.PreflightCheckPassed {
			klog.Infoln(fmt.Sprintf("PreflightcheckSummary is: %v.", result.Status.PreflightCheckSummary))
			return false, nil
		}
		return *result.Status.PreflightCheckSummary.PreflightCheckPassed, nil
	}
	if err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, condition); err != nil {
		return err
	}
	return nil
}

// waitForVMRuntimeReady checks on the status of VMRuntime every given polling
// interval up to the given maximum time , will return context timeout error if
// VMRuntime status failed to become ready.
func waitForVMRuntimeReady(ctx context.Context, client *rest.RESTClient, interval, timeout time.Duration) error {
	condition := func(ctx context.Context) (bool, error) {
		result := vmruntimev1.VMRuntime{}
		err := client.Get().Resource("vmruntimes").Name("vmruntime").Do(ctx).Into(&result)
		if err != nil {
			return false, err
		}
		klog.Infoln(fmt.Sprintf("VMRuntime status is: %v.", result.Status.Ready))
		return result.Status.Ready, nil
	}
	if err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, condition); err != nil {
		return err
	}
	return nil
}

// createTestVMonNode takes vmConfig and node name to create VM on
// and create a VM with given vmConfig on the node specified.
func createTestVMonNode(vmConfig VMTestConfig, nodeName string, restClient *rest.RESTClient, virtClient kubecli.KubevirtClient, ctx context.Context, interval, timeout time.Duration) (*gvmv1.VirtualMachine, error) {
	var err error
	vmDiskName := generateDiskName(vmConfig.Name)
	err = createAndWaitDataVolumeOnNodeToSucceedByName(vmDiskName, nodeName, virtClient, ctx, interval, timeout)
	if err != nil {
		klog.Errorf("Failed to create DataVolume for test VM %s : %s", vmConfig.Name, err)
		return nil, err
	}
	err = createAndWaitDiskToSucceedByName(vmDiskName, restClient, ctx, interval, timeout)
	if err != nil {
		klog.Errorf("Failed to create Disk for test VM %s : %s", vmConfig.Name, err)
		return nil, err
	}

	networkInterfaces := []gvmv1.InterfaceSpec{defaultNetworkInterface}
	for _, networkInterface := range vmConfig.NetworkInterfaces {
		networkInterfaces = append(networkInterfaces, gvmv1.InterfaceSpec{
			Name: networkInterface.Name,
			NetworkInterfaceSpec: &networkv1.NetworkInterfaceSpec{
				NetworkName: networkInterface.NetworkName,
				IpAddresses: []string{networkInterface.IPAddress},
			},
			Default: true,
		})
	}

	vmObject := &gvmv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vmConfig.Name,
			Namespace: vmConfig.Namespace,
		},
		Spec: gvmv1.VirtualMachineSpec{
			OSType:                           vmConfig.OSType,
			Interfaces:                       networkInterfaces,
			AutoRestartOnConfigurationChange: true,
			Compute: gvmv1.Compute{
				CPU:    &gvmv1.CPU{VCPUs: 2},
				Memory: &gvmv1.Memory{Capacity: resource.MustParse("4Gi")},
			},
			Disks: []gvmv1.Disk{
				{
					VirtualMachineDiskName: vmDiskName,
					Boot:                   true,
				},
			},
			Scheduling: &gvmv1.Scheduling{
				NodeSelector: map[string]string{k8sNodeNameLabelKey: nodeName},
			},
		},
	}

	addDefaultLoginCredentials(vmObject)

	createdVM, err := waitForGVMRunning(vmObject, ctx, restClient, interval, timeout)
	if err != nil {
		return nil, err
	}

	return createdVM, nil
}

// addDefaultLoginCredentials add default login account: root and password:
// google when the operating system is Linux.
func addDefaultLoginCredentials(vm *gvmv1.VirtualMachine) {
	if vm.Spec.OSType == gvmv1.OSTypeLinux {
		annotations := vm.ObjectMeta.Annotations
		if annotations == nil {
			annotations = make(map[string]string)
		}
		annotations["vm.cluster.gke.io/configure-initial-password"] = "root:google"
		vm.ObjectMeta.Annotations = annotations
	}
}

// createAndWaitDiskToSucceedByName creates a VM disk by given name and wait for
// the disk to be in success phase. Will return the context time exceed error if
// the vm disk failed to achieve success phase.
func createAndWaitDiskToSucceedByName(diskName string, restClient *rest.RESTClient, ctx context.Context, interval, timeout time.Duration) error {
	vmDiskToCreate := gvmv1.VirtualMachineDisk{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "vm.cluster.gke.io/v1",
			Kind:       "VirtualMachineDisk",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      diskName,
			Namespace: "default",
		},
		Spec: gvmv1.VirtualMachineDiskSpec{
			PersistentVolumeClaimName: ptr.To(diskName),
		},
	}

	vmDiskToCreateBody, err := json.Marshal(vmDiskToCreate)
	creationResult := gvmv1.VirtualMachineDisk{}
	err = restClient.Post().Namespace(vmDiskToCreate.Namespace).Resource("virtualmachinedisks").Body(vmDiskToCreateBody).Do(ctx).Into(&creationResult)
	if err != nil {
		if kerrors.IsAlreadyExists(err) {
			klog.Infoln("Disk already exist.")
			return nil
		}
		return err
	}
	condition := func(ctx context.Context) (bool, error) {
		result := gvmv1.VirtualMachineDisk{}
		err := restClient.Get().Namespace(vmDiskToCreate.Namespace).Resource("virtualmachinedisks").Name(diskName).Do(ctx).Into(&result)
		if err != nil {
			return false, err
		}
		klog.Infoln(fmt.Sprintf("Current VMDisk %s Phase: %s, Progress: %s", result.Name, result.Status.Phase, result.Status.Progress))
		return result.Status.Phase == gvmv1.DiskPhaseSucceeded, nil
	}
	if err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, condition); err != nil {
		klog.Infoln("current error: %s", err)
		return err
	}
	return nil
}

// createAndWaitDataVolumeOnNodeToSucceedByName creates a DataVolume by given
// name and wait for the DataVolume to be in success phase. Will return the
// context time exceed error if the DataVolume failed to achieve success phase.
func createAndWaitDataVolumeOnNodeToSucceedByName(diskName string, nodeName string, virtClient kubecli.KubevirtClient, ctx context.Context, interval, timeout time.Duration) error {
	resourceList := map[corev1.ResourceName]resource.Quantity{}
	resourceList[corev1.ResourceStorage] = *resource.NewQuantity(5*1024*1024*1024, resource.BinarySI)
	dataVolumeToCreate := cdiv1beta1.DataVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      diskName,
			Namespace: "default",
		},

		Spec: cdiv1beta1.DataVolumeSpec{
			Source: &cdiv1beta1.DataVolumeSource{HTTP: &cdiv1beta1.DataVolumeSourceHTTP{URL: "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"}},
			PVC: &corev1.PersistentVolumeClaimSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{k8sNodeNameLabelKey: nodeName},
				},
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: resourceList,
				},
				StorageClassName: ptr.To("local-shared"),
			},
		},
	}

	_, err := virtClient.CdiClient().CdiV1beta1().DataVolumes(dataVolumeToCreate.Namespace).Create(ctx, &dataVolumeToCreate, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("Failed to create DataVolume: %s, %s", dataVolumeToCreate.Name, err)
	}

	condition := func(ctx context.Context) (bool, error) {
		dataVolumeCreated, err := virtClient.CdiClient().CdiV1beta1().DataVolumes(dataVolumeToCreate.Namespace).Get(ctx, dataVolumeToCreate.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		klog.Infoln(fmt.Sprintf("Current DataVolume %s Phase: %s, Progress: %s", dataVolumeCreated.Name, dataVolumeCreated.Status.Phase, dataVolumeCreated.Status.Progress))
		return dataVolumeCreated.Status.Phase == cdiv1beta1.Succeeded, nil
	}
	if err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, condition); err != nil {
		klog.Infoln("current error: %s", err)
		return err
	}
	return nil
}

// waitForGVMRunning create VM using the VM object given without any
// modification, the function will check on the status of the VM by the given
// pulling interval up to the maximum time. Will return the context time exceed
// error if the test VM failed to achieve running phase.
func waitForGVMRunning(gvm *gvmv1.VirtualMachine, ctx context.Context, restClient *rest.RESTClient, interval, timeout time.Duration) (*gvmv1.VirtualMachine, error) {
	klog.Infoln(fmt.Sprintf("GVM to be created:%s", prettyPrint(gvm)))

	creationResult := gvmv1.VirtualMachine{}
	if err := restClient.Post().Namespace(gvm.Namespace).Resource("virtualmachines").Body(gvm).Do(ctx).Into(&creationResult); err != nil {
		return nil, err
	}
	condition := func(ctx context.Context) (bool, error) {
		result := gvmv1.VirtualMachine{}
		err := restClient.Get().Namespace(gvm.Namespace).Resource("virtualmachines").Name(gvm.Name).Do(ctx).Into(&result)
		if err != nil {
			return false, err
		}
		klog.Infoln(fmt.Sprintf("Current VM %s state: %s", result.Name, result.Status.State))
		return result.Status.State == gvmv1.Running, nil
	}
	if err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, condition); err != nil {
		return nil, err
	}
	return &creationResult, nil
}

// teatDownAllTestVM tears down all the VMs and subsequent DataVolume and disk
// created in the test.
func teatDownTestVM(vmConfig VMTestConfig, restClient *rest.RESTClient, virtClient kubecli.KubevirtClient, ctx context.Context) error {
	var err error

	klog.Infoln("Tearing down DataVolume: ", generateDiskName(vmConfig.Name))
	err = virtClient.CdiClient().CdiV1beta1().DataVolumes(vmConfig.Namespace).Delete(ctx, generateDiskName(vmConfig.Name), metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	klog.Infoln("Tearing down VMDisk: ", generateDiskName(vmConfig.Name))
	diskDeLeteResult := gvmv1.VirtualMachineDisk{}
	err = restClient.Delete().Namespace(vmConfig.Namespace).Name(generateDiskName(vmConfig.Name)).Resource("virtualmachinedisks").Do(ctx).Into(&diskDeLeteResult)
	if err != nil {
		return err
	}
	klog.Infoln("Tearing down VM: ", vmConfig.Name)
	gvmDeleteResult := gvmv1.VirtualMachine{}
	if err = restClient.Delete().Namespace(vmConfig.Namespace).Resource("virtualmachines").Name(vmConfig.Name).Do(ctx).Into(&gvmDeleteResult); err != nil {
		return err
	}
	return nil
}

// generateDiskName generate a disk name for a  given GVM name.
func generateDiskName(gvmName string) string {
	return fmt.Sprintf("%s-disk", gvmName)
}
func MakePingCommand(DestinationVMIPstr string) string {
	ipACmd := "ip a"
	ipRCmd := "ip r"
	pingCmd := fmt.Sprintf("ping -c 5 %s\n", DestinationVMIPstr)
	return fmt.Sprintf("%s && %s && %s", ipACmd, ipRCmd, pingCmd)
}
