package option

const (
	// SynchronizeK8sWindowsNodes creates corresponding CiliumNode resource for Windows node.
	SynchronizeK8sWindowsNodes = "synchronize-k8s-windows-nodes"
	// EnableGoogleMultiNIC is the name of the option to enable gogole multi NIC support.
	EnableGoogleMultiNIC = "enable-google-multi-nic"
	// SynchronizeMigratingNodes creates corresponding CiliumNode resource for Migrating calico nodes.
	SynchronizeMigratingNodes = "synchronize-migrating-nodes"

	// Enable mTLSfor metrics server
	OperatorEnableMetricsServerTLS = "operator-enable-metrics-server-tls"

	// MetricsServerTLSCertFile specifies the path to the public key file for
	// the metrics server. The file must contain PEM encoded data.
	OperatorMetricsServerTLSCertFile = "operator-metrics-server-tls-cert-file"

	// MetricsServerTLSKeyFile specifies the path to the private key file for
	// the metrics server. The file must contain PEM encoded data.
	OperatorMetricsServerTLSKeyFile = "operator-metrics-server-tls-key-file"

	// MetricsServerTLSClientCAFiles specifies the path to one or more client
	// CA certificates to use for TLS with mutual authentication (mTLS) on the
	// metrics server. The files must contain PEM encoded data.
	OperatorMetricsServerTLSClientCAFiles = "operator-metrics-server-tls-client-ca-files"
)
