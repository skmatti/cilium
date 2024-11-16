package util

import (
	"context"
	"fmt"
	"time" // Do not use pkg/time in test code.

	"k8s.io/apimachinery/pkg/util/wait"
	virtv1 "kubevirt.io/api/core/v1"
	cdiv1beta1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/kubevm/util/pkg/errors"
	vmv1 "gke-internal.googlesource.com/third_party/cilium/google_test/wora/e2e/pkg/kubevm/vm-controller/api/v1"
)

// VMResources defines vm resources.
type VMResources struct {
	gvmList     vmv1.VirtualMachineList
	gvmDiskList vmv1.VirtualMachineDiskList
	vmTypeList  vmv1.VirtualMachineTypeList
	vmList      virtv1.VirtualMachineList
	vmiList     virtv1.VirtualMachineInstanceList
	dvList      cdiv1beta1.DataVolumeList
}

// WaitDeleted is used to wait for vm resource deletion.
func WaitDeleted(ctx context.Context, k8sClient client.Client, timeout time.Duration, printFunc func(args ...int)) error {
	return wait.PollUntilContextTimeout(ctx, 10*time.Second, timeout, true, func(context.Context) (bool, error) {
		resources, err := getAllVMResourcesForDeletion(ctx, k8sClient)
		if err != nil {
			return false, err
		}
		vmNum := len(resources.vmList.Items)
		vmiNum := len(resources.vmiList.Items)
		dvNum := len(resources.dvList.Items)
		gvmNum := len(resources.gvmList.Items)
		gvmDiskNum := len(resources.gvmDiskList.Items)
		vmTypeNum := len(resources.vmTypeList.Items)
		printFunc(gvmNum, gvmDiskNum, vmTypeNum, vmNum, vmiNum, dvNum)
		return vmNum == 0 && vmiNum == 0 && dvNum == 0 && gvmNum == 0 && gvmDiskNum == 0 && vmTypeNum == 0, nil
	})
}

func getAllVMResourcesForDeletion(ctx context.Context, k8sClient client.Client) (*VMResources, error) {
	resources := &VMResources{}
	if err := k8sClient.List(ctx, &resources.gvmList); err != nil && !errors.HasNoMatchError(err) {
		return nil, fmt.Errorf("failed to list GVMs: %w", err)
	}
	if err := k8sClient.List(ctx, &resources.gvmDiskList); err != nil && !errors.HasNoMatchError(err) {
		return nil, fmt.Errorf("failed to list GVM disks: %w", err)
	}
	if err := k8sClient.List(ctx, &resources.vmTypeList); err != nil && !errors.HasNoMatchError(err) {
		return nil, fmt.Errorf("failed to list VM type: %w", err)
	}
	if err := k8sClient.List(ctx, &resources.vmList); err != nil && !errors.HasNoMatchError(err) {
		return nil, fmt.Errorf("failed to list VMs: %w", err)
	}
	if err := k8sClient.List(ctx, &resources.vmiList); err != nil && !errors.HasNoMatchError(err) {
		return nil, fmt.Errorf("failed to list VMIs: %w", err)
	}
	if err := k8sClient.List(ctx, &resources.dvList); err != nil && !errors.HasNoMatchError(err) {
		return nil, fmt.Errorf("failed to list DVs: %w", err)
	}
	return resources, nil
}
