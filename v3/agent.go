package sshman

import (
	"crypto"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func AddKeyToSSHAgent[T any](input T) (err error) {
	var (
		privateKeyBytes         []byte
		privateKeyPasswordBytes []byte
		privateKey              crypto.PrivateKey
		certificate             *ssh.Certificate
	)

	switch inputTypeAsserted := any(input).(type) {
	case *KeyPair:
		_, _, err = inputTypeAsserted.Parse()
		if err != nil {
			return fmt.Errorf("invalid input of type sshman.KeyPair: %w", err)
		}

		privateKeyBytes = inputTypeAsserted.PrivateKey
		privateKeyPasswordBytes = inputTypeAsserted.PrivateKeyPassword
	case *SSH:
		_, _, certificate, err = inputTypeAsserted.Parse()
		if err != nil {
			return fmt.Errorf("invalid input of type sshman.SSH: %w", err)
		}
		privateKeyBytes = inputTypeAsserted.PrivateKey
		privateKeyPasswordBytes = inputTypeAsserted.PrivateKeyPassword

	default:
		return fmt.Errorf("unsupported input type %T: only sshman.KeyPair or sshman.SSH", input)
	}

	if privateKeyPasswordBytes != nil {
		privateKey, err = ssh.ParseRawPrivateKeyWithPassphrase(privateKeyBytes, privateKeyPasswordBytes)
		if err != nil {
			return fmt.Errorf("error parsing private key with password: %w", err)
		}
	} else {
		privateKey, err = ssh.ParseRawPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return fmt.Errorf("SSH_AUTH_SOCK environment variable not set")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return fmt.Errorf("error connecting to SSH agent: %w", err)
	}
	defer conn.Close()

	agentClient := agent.NewClient(conn)

	agentAddKey := agent.AddedKey{
		PrivateKey: privateKey,
	}

	if certificate != nil {
		agentAddKey.Certificate = certificate
	}

	err = agentClient.Add(agentAddKey)
	if err != nil {
		return fmt.Errorf("error adding key to agent: %w", err)
	}

	return nil
}
