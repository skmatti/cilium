package option

const (
	// SynchronizeK8sWindowsNodes creates corresponding CiliumNode resource for Windows node.
	SynchronizeK8sWindowsNodes = "synchronize-k8s-windows-nodes"

	// SynchronizeMigratingNodes creates corresponding CiliumNode resource for Migrating calico nodes.
	SynchronizeMigratingNodes = "synchronize-migrating-nodes"
)
