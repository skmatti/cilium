package utils

import "path/filepath"

// ClusterArtifacts represents the file paths to EKP cluster artifacts.
type ClusterArtifacts struct {
	InfraYaml  string
	Metadata   string
	SSHKey     string
	KubeConfig string
}

// NewClusterArtifacts returns ClusterArtifacts containing artifact filepaths in artifactsDir.
func NewClusterArtifacts(artifactsDir string) *ClusterArtifacts {
	return &ClusterArtifacts{
		InfraYaml:  filepath.Join(artifactsDir, "infra.yaml"),
		Metadata:   filepath.Join(artifactsDir, "artifacts/metadata.json"),
		SSHKey:     filepath.Join(artifactsDir, "artifacts/id_rsa"),
		KubeConfig: filepath.Join(artifactsDir, "artifacts/kubeconfig"),
	}
}
