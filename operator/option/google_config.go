package option

const (
	// SynchronizeK8sWindowsNodes creates corresponding CiliumNode resource for Windows node.
	SynchronizeK8sWindowsNodes = "synchronize-k8s-windows-nodes"
	// EnableGoogleMultiNIC is the name of the option to enable gogole multi NIC support.
	EnableGoogleMultiNIC = "enable-google-multi-nic"
	// SynchronizeMigratingNodes creates corresponding CiliumNode resource for Migrating calico nodes.
	SynchronizeMigratingNodes = "synchronize-migrating-nodes"
)
