package kubevirt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"time" // Do not use pkg/time in test code.

	expect "github.com/google/goexpect"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	networkclientset "github.com/GoogleCloudPlatform/gke-networking-api/client/network/clientset/versioned"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/kubectl/pkg/scheme"

	"kubevirt.io/client-go/kubecli"
	cdiv1beta1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"

	"gke-internal.googlesource.com/anthos-networking/test-infra/pkg/client"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
	gvmv1 "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/kubevm/vm-controller/api/v1"
	vmruntimev1 "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/kubevm/vm-runtime-operator/api/v1"
	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/utils"
	waitutil "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/test/wait"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	virtv1 "kubevirt.io/api/core/v1"
)

// networkIP holds IPs to corresponding network names.
type networkIP map[string]string

// networkConnection holds networks and default network which the workload connects to.
type networkConnection struct {
	networkIPs     networkIP
	defaultNetwork string
}

type VMDetails struct {
	IP   string
	Node string
}

type TearDownConfig struct {
	VMName    string
	Namespace string
	DiskName  string
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
		if result.Status.PreflightCheckSummary == nil || result.Status.PreflightCheckSummary.PreflightCheckPassed == nil || !*result.Status.PreflightCheckSummary.PreflightCheckPassed {
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

// tearDownAllTestVM tears down all the VMs and subsequent DataVolume and disk
// created in the test.
func tearDownTestVM(vmConfig TearDownConfig, restClient *rest.RESTClient, virtClient kubecli.KubevirtClient, ctx context.Context) error {
	var err error

	klog.Infoln("Tearing down DataVolume: ", vmConfig.DiskName)
	err = virtClient.CdiClient().CdiV1beta1().DataVolumes(vmConfig.Namespace).Delete(ctx, vmConfig.DiskName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	klog.Infoln("Tearing down VMDisk: ", vmConfig.DiskName)
	diskDeLeteResult := gvmv1.VirtualMachineDisk{}
	err = restClient.Delete().Namespace(vmConfig.Namespace).Name(vmConfig.DiskName).Resource("virtualmachinedisks").Do(ctx).Into(&diskDeLeteResult)
	if err != nil {
		return err
	}
	klog.Infoln("Tearing down VM: ", vmConfig.VMName)
	gvmDeleteResult := gvmv1.VirtualMachine{}
	if err = restClient.Delete().Namespace(vmConfig.Namespace).Resource("virtualmachines").Name(vmConfig.VMName).Do(ctx).Into(&gvmDeleteResult); err != nil {
		return err
	}
	return nil
}

// tearDownStatefulSetAndWait deletes a specific statefulset and waits for it to be fully terminated.
func tearDownStatefulSetAndWait(ctx context.Context, cl k8sclient.Client, namespace, stsName string) error {
	klog.Infof("Tearing down and waiting for StatefulSet: %s/%s", namespace, stsName)
	stsToDelete := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      stsName,
			Namespace: namespace,
		},
	}
	// utils.DeleteAndWait can handle any Kubernetes object, so it works here too.
	return utils.DeleteAndWait(ctx, cl, stsToDelete)
}

// tearDownServiceAndWait deletes a specific service and waits for it to be fully terminated.
func tearDownServiceAndWait(ctx context.Context, cl k8sclient.Client, namespace, serviceName string) error {
	klog.Infof("Tearing down and waiting for Service: %s/%s", namespace, serviceName)
	svcToDelete := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: namespace,
		},
	}
	return utils.DeleteAndWait(ctx, cl, svcToDelete)
}

// tearDownStorageClassAndWait deletes a specific storage class and waits for it to be fully terminated.
func tearDownStorageClassAndWait(ctx context.Context, cl k8sclient.Client, scName string) error {
	klog.Infof("Tearing down and waiting for StorageClass: %s", scName)
	scToDelete := &storagev1.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: scName,
		},
	}
	return utils.DeleteAndWait(ctx, cl, scToDelete)
}

func waitForVMDeletionWithIntervalAndTimeout(ctx context.Context, vc kubecli.KubevirtClient, ns, name string) error {
	return waitutil.WaitForSuccessContext(ctx, "VM deletion successful", waitutil.WaitingLong, func(ctx context.Context) error {
		if _, err := vc.VirtualMachineInstance(ns).Get(ctx, name, metav1.GetOptions{}); err != nil {
			if apierrors.IsNotFound(err) {
				klog.Infof("VirtualMachine %s/%s is deleted", ns, name)
				return nil
			}
			return fmt.Errorf("Failed to get VirtualMachine %s/%s: %s", ns, name, err)
		}
		return fmt.Errorf("Waiting VirtualMachine %s/%s to be deleted", ns, name)
	})
}

// ConfigureAndAwaitDHCP creates the DHCP configurator pod in configuring the dhcp server and waits for it to complete.
func configureAndAwaitDHCPviaPod(ctx context.Context, clientset client.Interface, namespace string, nodeName string, timeout time.Duration) error {
	podName := "dhcp-configurator-pod"
	dhcpconfigpod := fmt.Sprintf(dhcpConfiguratorPodYAML, podName, nodeName)
	err := utils.KubectlApply(dhcpconfigpod)
	if err != nil {
		return fmt.Errorf("failed to apply DHCP configurator pod: %w", err)
	}
	klog.Infof("Waiting up to %s for Pod %s to complete...", timeout, podName)
	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err = wait.PollUntilContextCancel(pollCtx, 15*time.Second, true, func(ctx context.Context) (bool, error) {
		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to get pod %s: %w", podName, err)
		}
		switch pod.Status.Phase {
		case corev1.PodSucceeded:
			klog.Infof("Pod %s completed successfully.", podName)
			return true, nil
		case corev1.PodFailed:
			return false, fmt.Errorf("pod %s failed", podName)
		case corev1.PodPending, corev1.PodRunning:
			return false, nil
		default:
			return false, fmt.Errorf("pod %s in unexpected phase: %s", podName, pod.Status.Phase)
		}
	})
	if err != nil {
		return fmt.Errorf("pod %s did not complete successfully: %w", podName, err)
	}
	klog.Infof("deleting completed pod %s", podName)
	deleteErr := clientset.CoreV1().Pods(namespace).Delete(ctx, podName, metav1.DeleteOptions{})
	if deleteErr != nil {
		if !errors.IsNotFound(deleteErr) {
			return fmt.Errorf("failed to delete completed pod %s: %w", podName, deleteErr)
		}
	}
	return nil
}

// WorkerNodes finds all nodes matching the predefined label selector.
func workerNodes(ctx context.Context, c client.Interface) ([]corev1.Node, error) {
	nodeList, err := c.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: workerNodeLabelSelectorString})
	if err != nil {
		return nil, fmt.Errorf("failed to list worker nodes: %w", err)
	}
	if len(nodeList.Items) == 0 {
		return nil, fmt.Errorf("no worker nodes found with label selector: %s", workerNodeLabelSelectorString)
	}
	return nodeList.Items, nil
}

// VerifyVMIPFromDHCPRange fetches the VM's IP and checks if it's in the DHCP range.
func verifyVMIPFromDHCPRange(ctx context.Context, virtClient kubecli.KubevirtClient, vmName, namespace string, dhcpRangeStart, dhcpRangeEnd string) error {
	klog.Infof("Verifying IP for VM %s/%s", namespace, vmName)
	rangeStartIP := net.ParseIP(dhcpRangeStart)
	rangeEndIP := net.ParseIP(dhcpRangeEnd)
	if rangeStartIP == nil || rangeEndIP == nil {
		return fmt.Errorf("invalid DHCP IP range: %s - %s", dhcpRangeStart, dhcpRangeEnd)
	}
	vmi, err := virtClient.VirtualMachineInstance(namespace).Get(ctx, vmName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get VMI %s/%s: %w", namespace, vmName, err)
	}
	if vmi.Status.Phase != virtv1.Running {
		return fmt.Errorf("vm %s/%s is not in Running phase, current phase: %s", namespace, vmName, vmi.Status.Phase)
	}
	if len(vmi.Status.Interfaces) == 0 {
		return fmt.Errorf("vm %s/%s has no interfaces in status", namespace, vmName)
	}
	var vmIP net.IP
	for _, iface := range vmi.Status.Interfaces {
		var ipStr string
		if len(iface.IPs) > 0 {
			ipStr = iface.IPs[0]
		} else if iface.IP != "" {
			ipStr = iface.IP
		} else {
			continue
		}
		vmIP = net.ParseIP(ipStr)
		if vmIP == nil {
			klog.Warningf("VM %s/%s has invalid IP string '%s' on interface %s. Checking next interface.", namespace, vmName, ipStr, iface.Name)
			continue
		}
		klog.Infof("Found ip %s on interface %s for VM %s/%s", vmIP.String(), iface.Name, namespace, vmName)
		break
	}
	if vmIP == nil {
		return fmt.Errorf("no valid ip found on any interface for VM %s/%s", namespace, vmName)
	}
	if bytes.Compare(vmIP.To4(), rangeStartIP.To4()) >= 0 && bytes.Compare(vmIP.To4(), rangeEndIP.To4()) <= 0 {
		klog.Infof("SUCCESS: vm %s/%s ip %s is within the DHCP range [%s - %s]", namespace, vmName, vmIP, rangeStartIP, rangeEndIP)
		return nil
	}
	return fmt.Errorf("vm %s/%s ip %s is outside the expected DHCP range [%s - %s]", namespace, vmName, vmIP, rangeStartIP, rangeEndIP)
}

// check if the vmi is in running phase
func runningVMI(ctx context.Context, virtClient kubecli.KubevirtClient, vmName, namespace string) (*virtv1.VirtualMachineInstance, error) {
	vmi, err := virtClient.VirtualMachineInstance(namespace).Get(ctx, vmName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get VMI %s/%s: %w", namespace, vmName, err)
	}
	if vmi.Status.Phase != virtv1.Running {
		return nil, fmt.Errorf("vm %s/%s is not in Running phase, current phase: %s", namespace, vmName, vmi.Status.Phase)
	}

	return vmi, nil
}

// vmIP fetches the primary IP address of the VM.
func vmIP(ctx context.Context, virtClient kubecli.KubevirtClient, vmName, namespace string) (string, error) {
	vmi, err := runningVMI(ctx, virtClient, vmName, namespace)
	if err != nil {
		return "", err
	}
	if len(vmi.Status.Interfaces) == 0 {
		return "", fmt.Errorf("vm %s/%s has no interfaces in status", namespace, vmName)
	}
	var ipAddress string
	if len(vmi.Status.Interfaces[0].IPs) > 0 {
		ipAddress = vmi.Status.Interfaces[0].IPs[0]
	} else if vmi.Status.Interfaces[0].IP != "" {
		ipAddress = vmi.Status.Interfaces[0].IP
	} else {
		return "", fmt.Errorf("vm %s/%s interface %s has no ip's listed", namespace, vmName, vmi.Status.Interfaces[0].Name)
	}
	return ipAddress, nil
}

func consolePing(virtClient kubecli.KubevirtClient, vmi *virtv1.VirtualMachineInstance, ipToPing string) error {
	const pingTimeout = 60 * time.Second
	klog.Infof("Attempting to ping %s from VM %s...", ipToPing, vmi.Name)
	cmd := fmt.Sprintf("ping -c 5 %s\n", ipToPing)
	expectedString := "5 received"
	expecter, _, err := NewExpecter(virtClient, vmi, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to create expecter: %w", err)
	}
	defer expecter.Close()
	expects := []expect.Batcher{
		&expect.BSnd{S: cmd},
		&expect.BExp{R: expectedString},
	}
	resp, err := expecter.ExpectBatch(expects, pingTimeout)
	klog.Infof("Console output for VM %s ping: %v", vmi.Name, resp)
	if err != nil {
		return fmt.Errorf("ping to %s failed. Did not find '%s': %w", ipToPing, expectedString, err)
	}
	klog.Infof("Successfully pinged %s from VM %s.", ipToPing, vmi.Name)
	return nil
}

// VMDetails fetches the VMI and returns its primary IP and the node it's scheduled on.
func vmDetailsLivemigration(ctx context.Context, virtClient kubecli.KubevirtClient, vmName, namespace string) (*VMDetails, error) {
	vmi, err := runningVMI(ctx, virtClient, vmName, namespace)
	if err != nil {
		return nil, err
	}
	nodeName := vmi.Status.NodeName
	if nodeName == "" {
		return nil, fmt.Errorf("vm %s/%s is not yet scheduled to a node", namespace, vmName)
	}
	if len(vmi.Status.Interfaces) == 0 {
		return nil, fmt.Errorf("vm %s/%s has no interfaces in status", namespace, vmName)
	}
	var ipAddress string
	if len(vmi.Status.Interfaces[0].IPs) > 0 {
		ipAddress = vmi.Status.Interfaces[0].IPs[0]
	} else if vmi.Status.Interfaces[0].IP != "" {
		ipAddress = vmi.Status.Interfaces[0].IP
	} else {
		return nil, fmt.Errorf("vm %s/%s interface %s has no IPs listed", namespace, vmName, vmi.Status.Interfaces[0].Name)
	}
	return &VMDetails{IP: ipAddress, Node: nodeName}, nil
}

// CheckVMMigratable checks if the vm is the LiveMigratable
func checkVMMigratable(ctx context.Context, virtClient kubecli.KubevirtClient, vmName, namespace string) error {
	vmi, err := virtClient.VirtualMachineInstance(namespace).Get(ctx, vmName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	for _, cond := range vmi.Status.Conditions {
		if cond.Type == virtv1.VirtualMachineInstanceIsMigratable && cond.Status == corev1.ConditionTrue {
			return nil
		}
	}
	return fmt.Errorf("vm %s/%s is not LiveMigratable. Conditions: %v", namespace, vmName, vmi.Status.Conditions)
}

func startVMMigration(ctx context.Context, virtClient kubecli.KubevirtClient, vmName, namespace, migrationName string) (*virtv1.VirtualMachineInstanceMigration, error) {
	migration := &virtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      migrationName,
			Namespace: namespace,
		},
		Spec: virtv1.VirtualMachineInstanceMigrationSpec{
			VMIName: vmName,
		},
	}
	createdMigration, err := virtClient.VirtualMachineInstanceMigration(namespace).Create(ctx, migration, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create VMIM object %s/%s: %w", migrationName, namespace, err)
	}
	return createdMigration, nil
}

func waitForMigrationToSucceed(ctx context.Context, virtClient kubecli.KubevirtClient, migrationName, namespace string, timeout time.Duration) error {
	pollErr := wait.PollUntilContextTimeout(ctx, 30*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		vmim, err := virtClient.VirtualMachineInstanceMigration(namespace).Get(ctx, migrationName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		switch vmim.Status.Phase {
		case virtv1.MigrationSucceeded:
			return true, nil
		case virtv1.MigrationFailed:
			return false, fmt.Errorf("migration %s/%s failed. Status: %v", namespace, migrationName, vmim.Status)
		default:
			klog.Infof("Migration %s is in phase: %s", migrationName, vmim.Status.Phase)
			return false, nil
		}
	})
	if pollErr != nil {
		return fmt.Errorf("failed waiting for migration %s/%s to succeed: %w", namespace, migrationName, pollErr)
	}
	return nil
}

func performVMLiveMigrationTest(ctx context.Context, vc kubecli.KubevirtClient, vmName string, vmNamespace string) error {
	klog.Infof("Fetching initial details for VM '%s'...", vmName)
	originalDetails, err := vmDetailsLivemigration(ctx, vc, vmName, vmNamespace)
	if err != nil {
		return fmt.Errorf("failed to get initial VM details: %w", err)
	}
	klog.Infof("Successfully fetched initial details! IP: %s, Node: %s", originalDetails.IP, originalDetails.Node)
	klog.Infof("Checking if VM is migratable...")
	if err := checkVMMigratable(ctx, vc, vmName, vmNamespace); err != nil {
		return fmt.Errorf("VM is not in a migratable state: %w", err)
	}
	klog.Infof("VM is ready for migration.")
	migrationName := fmt.Sprintf("migrate-%s-%d", vmName, time.Now().UnixNano())
	klog.Infof("Starting migration '%s'...", migrationName)
	if _, err := startVMMigration(ctx, vc, vmName, vmNamespace, migrationName); err != nil {
		return fmt.Errorf("failed to create migration object: %w", err)
	}
	klog.Infof("Migration object created. Waiting for completion...")
	if err := waitForMigrationToSucceed(ctx, vc, migrationName, vmNamespace, 5*time.Minute); err != nil {
		return fmt.Errorf("migration failed to complete: %w", err)
	}
	klog.Infof("Migration Succeeded!")
	var newDetails *VMDetails
	klog.Infof("Polling for VM to report being on a new node...")
	pollErr := wait.PollUntilContextTimeout(ctx, 5*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		var getDetailsErr error
		newDetails, getDetailsErr = vmDetailsLivemigration(ctx, vc, vmName, vmNamespace)
		if getDetailsErr != nil {
			klog.Infof("warning: failed to get VM details during poll: %v. Retrying...", getDetailsErr)
			return false, nil
		}
		if newDetails.Node == originalDetails.Node {
			klog.Infof("vm is still on the original node (%s). Waiting for it to move...", originalDetails.Node)
			return false, nil
		}
		return true, nil
	})
	if pollErr != nil {
		return fmt.Errorf("timed out waiting for VM to move to a new node: %w", pollErr)
	}
	klog.Infof("successfully confirmed VM has moved to a new node: %s", newDetails.Node)
	klog.Infof("comparing final results...")
	klog.Infof("original ip: %s, new ip: %s", originalDetails.IP, newDetails.IP)
	klog.Infof("original node: %s, new node: %s", originalDetails.Node, newDetails.Node)

	if newDetails.IP != originalDetails.IP {
		return fmt.Errorf("ip address changed after migration! original: %s, New: %s", originalDetails.IP, newDetails.IP)
	}
	if newDetails.Node == originalDetails.Node {
		return fmt.Errorf("node did not change after migration! still on: %s", originalDetails.Node)
	}
	klog.Infof("vm successfully migrated to a new node and kept the same IP.")
	return nil
}

// verifyNFSResources waits for the StatefulSet, its Pod, and its PVC to become ready.
func verifyNFStatefulSet(ctx context.Context, c client.Interface, namespace string, serverName string) error {
	statefulSetName := serverName
	klog.Infof("Waiting for StatefulSet '%s' to become ready...", statefulSetName)
	err := wait.PollUntilContextTimeout(ctx, 10*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		sts, err := c.AppsV1().StatefulSets(namespace).Get(ctx, statefulSetName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if sts.Status.ReadyReplicas == 1 {
			klog.Infof("StatefulSet '%s' is ready with %d replicas.", statefulSetName, sts.Status.ReadyReplicas)
			return true, nil
		}
		klog.Infof("Waiting for StatefulSet... Ready replicas: %d/1", sts.Status.ReadyReplicas)
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("statefulSet '%s' did not become ready: %w", statefulSetName, err)
	}
	klog.Info("Verifying NFS server pod is running...")
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		podList, err := c.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=nfs-server"})
		if err != nil {
			return false, err
		}
		if len(podList.Items) != 1 {
			klog.Infof("Waiting for NFS pod to be created (found %d pods)...", len(podList.Items))
			return false, nil
		}
		pod := podList.Items[0]
		if pod.Status.Phase == corev1.PodRunning {
			klog.Infof("Pod '%s' is running successfully.", pod.Name)
			return true, nil
		}
		klog.Infof("Waiting for pod '%s' to be Running, current status: %s", pod.Name, pod.Status.Phase)
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("pod verification failed: %w", err)
	}
	return nil
}

// waitForNFSReady waits for all the NFS components to become ready.
func waitForNFSReady(c client.Interface) error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), nfsInstallDuration)
	defer cancelFunc()
	return wait.PollUntilContextCancel(ctx, defaultInterval, true, func(ctx context.Context) (done bool, err error) {
		availableComponents, err := checkNFSInstallation(c)
		if err != nil {
			return false, err
		}
		klog.Infof("Waiting for NFS components to be ready. Currently available: %v", availableComponents)
		if len(availableComponents) != numNFSComponent {
			return false, nil
		}
		err = verifyNFStatefulSet(ctx, c, namespace, nfsServiceName)
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

// checkNFSInstallation checks the status of the NFS components and returns the
// available components.
func checkNFSInstallation(client client.Interface) ([]string, error) {
	var availableComponents []string
	ctx, cancelFunc := context.WithTimeout(context.TODO(), defaultGetTimeout)
	defer cancelFunc()
	csiControllerDeployment, err := client.AppsV1().Deployments(nfsCSIComponentNamespace).Get(ctx, nfsCSIControllerDeployment, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if csiControllerDeployment.Status.AvailableReplicas == csiControllerDeployment.Status.Replicas {
		availableComponents = append(availableComponents, nfsCSIControllerDeployment)
	}
	csiNodeDaemonSet, err := client.AppsV1().DaemonSets(nfsCSIComponentNamespace).Get(ctx, nfsCSINodeDaemonSet, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if csiNodeDaemonSet.Status.NumberAvailable == csiNodeDaemonSet.Status.DesiredNumberScheduled {
		availableComponents = append(availableComponents, nfsCSINodeDaemonSet)
	}
	return availableComponents, nil
}

func installNFS(ctx context.Context, c client.Interface) error {
	err := utils.KubectlApply(nfsController)
	if err != nil {
		return fmt.Errorf("failed to apply nfsController: %w", err)
	}
	err = utils.KubectlApply(nfsNode)
	if err != nil {
		return fmt.Errorf("failed to apply nfsNode: %w", err)
	}
	err = utils.KubectlApply(csiDriver)
	if err != nil {
		return fmt.Errorf("failed to apply csiDriver: %w", err)
	}
	err = utils.KubectlApply(nfsServer)
	if err != nil {
		return fmt.Errorf("failed to apply nfsServer: %w", err)
	}
	err = utils.KubectlApply(rbaccsiNfscontroller)
	if err != nil {
		return fmt.Errorf("failed to apply rbaccsiNfscontroller: %w", err)
	}
	err = utils.KubectlApply(unMountsecrets)
	if err != nil {
		return fmt.Errorf("failed to apply unMountsecrets: %w", err)
	}
	err = utils.KubectlApply(nfsStorageClass)
	if err != nil {
		return fmt.Errorf("failed to apply NFS storage class '%s':", err)
	}
	return nil
}

func createTestDHCPVirtualMachine(ctx context.Context, client client.Interface, restClient *rest.RESTClient, vc kubecli.KubevirtClient, vmOpts CreateVMOptions, nodeName string, interval, timeout time.Duration) (*gvmv1.VirtualMachine, error) {
	secret, err := createPasswordAuthLinuxSecret(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create password secret: %w", err)
	}
	pvc, err := createDHCPDataVolume(ctx, vc, vmOpts, nodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to create data volume (PVC): %w", err)
	}
	if err := createAndWaitDiskToSucceedByName(pvc, restClient, ctx, interval, timeout); err != nil {
		return nil, fmt.Errorf("vm disk %s failed to become ready: %w", pvc, err)
	}
	vmObject := createDHCPVirtualMachine(vmOpts.Name, pvc, vmOpts.NetworkName, secret.Name, vmOpts.IPAddress, nodeName)
	createdVM, err := waitForGVMRunning(vmObject, ctx, restClient, interval, timeout)
	if err != nil {
		return nil, fmt.Errorf("vm %s failed to start: %w", vmOpts.Name, err)
	}
	return createdVM, nil
}

func enableRoutingOnBootstrap() error {
	cmd := exec.Command("/bin/sh", "-c", enableRouteOnBootstrap)
	stdout, err := cmd.Output()
	klog.Infof("output of enabling routing on bootstrap:%s", stdout)
	return err
}

// CreatePasswordAuthLinuxSecret creates the secret directly.
func createPasswordAuthLinuxSecret(ctx context.Context, client client.Interface) (*corev1.Secret, error) {
	userdata := map[string][]byte{
		"userdata": []byte(defaultCloudInit),
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("dhcp-cloud-init-%s", rand.String(5)),
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
		Data: userdata,
	}
	klog.Infof("Creating Secret '%s/%s'", secret.Namespace, secret.Name)
	createdSecret, err := client.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		if kerrors.IsAlreadyExists(err) {
			klog.Warningf("Secret '%s/%s' already exists. Getting the existing one.", secret.Namespace, secret.Name)
			return client.CoreV1().Secrets(secret.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
		}
		return nil, fmt.Errorf("failed to create secret '%s/%s': %w", secret.Namespace, secret.Name, err)
	}
	return createdSecret, nil
}

// CreateDHCPDataVolume creates a DataVolume for the DHCP server
func createDHCPDataVolume(ctx context.Context, virtClient kubecli.KubevirtClient, opts CreateVMOptions, nodeName string) (string, error) {
	klog.Infof("Creating DataVolume '%s/%s' for DHCP server", opts.Namespace, opts.VMDiskName)
	accessModes := []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
	if opts.StorageClassName == "nfs-csi" {
		klog.Infof("StorageClass is 'nfs-csi', setting AccessMode to ReadWriteMany")
		accessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
	}
	dataVolume := &cdiv1beta1.DataVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.VMDiskName,
			Namespace: opts.Namespace,
		},
		Spec: cdiv1beta1.DataVolumeSpec{
			Source: &cdiv1beta1.DataVolumeSource{
				HTTP: &cdiv1beta1.DataVolumeSourceHTTP{
					URL: "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img",
				},
			},
			PVC: &corev1.PersistentVolumeClaimSpec{
				AccessModes: accessModes,
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("5Gi"),
					},
				},
				StorageClassName: ptr.To(opts.StorageClassName),
			},
		},
	}
	if nodeName != "" {
		klog.Infof("Pinning DataVolume to node: %s", nodeName)
		dataVolume.Spec.PVC.Selector = &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"kubernetes.io/hostname": nodeName,
			},
		}
	}
	_, err := virtClient.CdiClient().CdiV1beta1().DataVolumes(opts.Namespace).Create(ctx, dataVolume, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			klog.Infof("DataVolume '%s/%s' already exists.", opts.Namespace, opts.VMDiskName)
		} else {
			return "", fmt.Errorf("failed to create DataVolume: %w", err)
		}
	} else {
		klog.Infof("DataVolume '%s/%s' created successfully.", opts.Namespace, opts.VMDiskName)
	}
	klog.Infof("Waiting for DataVolume '%s/%s' to complete import...", opts.Namespace, opts.VMDiskName)
	err = wait.PollUntilContextTimeout(ctx, 30*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		dv, err := virtClient.CdiClient().CdiV1beta1().DataVolumes(opts.Namespace).Get(ctx, opts.VMDiskName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				klog.Infof("DataVolume '%s/%s' not found yet...", opts.Namespace, opts.VMDiskName)
				return false, nil
			}
			return false, err
		}
		phase := dv.Status.Phase
		klog.Infof("DataVolume '%s/%s' is in phase %s", opts.Namespace, opts.VMDiskName, phase)
		switch phase {
		case cdiv1beta1.Succeeded:
			klog.Infof("DataVolume '%s/%s' import successful.", opts.Namespace, opts.VMDiskName)
			return true, nil
		case cdiv1beta1.Failed, cdiv1beta1.Unknown:
			return false, fmt.Errorf("dataVolume '%s/%s' entered failed/unknown state: %s", opts.Namespace, opts.VMDiskName, phase)
		default:
			return false, nil
		}
	})
	if err != nil {
		return "", fmt.Errorf("dataVolume '%s/%s' did not succeed: %w", opts.Namespace, opts.VMDiskName, err)
	}
	pvcName := opts.VMDiskName
	klog.Infof("DataVolume '%s/%s' is ready. Associated PVC: '%s/%s'", opts.Namespace, opts.VMDiskName, opts.Namespace, pvcName)
	return pvcName, nil
}

// CreateDHCPVirtualMachine creates a VirtualMachine object.
func createDHCPVirtualMachine(vmName, diskName, networkName, secretName, ipAddress string, nodeName string) *gvmv1.VirtualMachine {
	var ipAddresses []string
	var interfaces []gvmv1.InterfaceSpec
	if ipAddress != "" {
		ipAddresses = []string{ipAddress}
	}
	if vmName == "dhcp-server-vm" {
		interfaces = []gvmv1.InterfaceSpec{
			{
				Name: "pod",
				NetworkInterfaceSpec: &networkv1.NetworkInterfaceSpec{
					NetworkName: "pod-network",
				},
				Default: true,
			},
			{
				Name: "vxlan1",
				NetworkInterfaceSpec: &networkv1.NetworkInterfaceSpec{
					NetworkName: networkName,
					IpAddresses: ipAddresses,
				},
			},
		}
	} else {
		interfaces = []gvmv1.InterfaceSpec{
			{
				Name: "vxlan1",
				NetworkInterfaceSpec: &networkv1.NetworkInterfaceSpec{
					NetworkName: networkName,
					IpAddresses: ipAddresses,
				},
				Default: true,
			},
		}
	}
	vmObject := &gvmv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vmName,
			Namespace: "default",
			Labels: map[string]string{
				"bpvms/testvm-txhzt": "IncludedInBackupScope",
			},
		},
		Spec: gvmv1.VirtualMachineSpec{
			OSType: gvmv1.OSTypeLinux,
			CloudInit: &gvmv1.CloudInit{
				NoCloudSource: &virtv1.CloudInitNoCloudSource{
					UserDataSecretRef: &corev1.LocalObjectReference{
						Name: secretName,
					},
				},
			},
			Compute: gvmv1.Compute{
				CPU:    &gvmv1.CPU{VCPUs: 2},
				Memory: &gvmv1.Memory{Capacity: resource.MustParse("1Gi")},
			},
			Disks: []gvmv1.Disk{
				{
					VirtualMachineDiskName: diskName,
					Boot:                   true,
					AutoDelete:             true,
					Driver:                 "virtio",
				},
			},
			Interfaces: interfaces,
		},
	}
	if nodeName != "" {
		vmObject.Spec.Scheduling = &gvmv1.Scheduling{
			NodeSelector: map[string]string{
				"kubernetes.io/hostname": nodeName,
			},
		}
	}
	return vmObject
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
