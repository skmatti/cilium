package utils

import (
	"os"

	"golang.org/x/crypto/ssh"
)

// RunSSHCommand runs command on remote machine and returns the output.
func RunSSHCommand(user, sshKey, endpoint, cmd string) ([]byte, error) {
	client, err := GetSSHClient(user, sshKey, endpoint)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	return session.CombinedOutput(cmd)
}

// GetSSHClient returns ssh client for a remote machine.
func GetSSHClient(user, keyPath, endpoint string) (*ssh.Client, error) {
	config, err := getSSHConfig(user, keyPath)
	if err != nil {
		return nil, err
	}
	client, err := ssh.Dial("tcp", endpoint+":22", config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func getSSHConfig(user, keyPath string) (*ssh.ClientConfig, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}
