package sshman

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHHost(sshAsset *SSH, caPublicKeyBytes []byte) error {
	_, hostPrivateKey, hostCertificate, err := sshAsset.Parse()
	if err != nil {
		return fmt.Errorf("error parsing SSH host assets: %w", err)
	}

	hostCertPrivateKey, err := ssh.NewCertSigner(hostCertificate, hostPrivateKey)
	if err != nil {
		return fmt.Errorf("error creating a ssh.CertSigner for host: %w", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != "password" {
				return nil, errors.New("wrong password")
			}

			return &ssh.Permissions{}, nil
		},
	}

	serverConfig.AddHostKey(hostCertPrivateKey)

	caPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(caPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("error parsing CA public key: %w", err)
	}

	hostCertChecker := ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			return bytes.Equal(auth.Marshal(), caPublicKey.Marshal())
		},
	}

	clientConfig := &ssh.ClientConfig{
		User: hostCertificate.ValidPrincipals[0],
		Auth: []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := hostCertChecker.CheckHostKey(hostname, remote, key)
			if err != nil {
				return fmt.Errorf("failed to authenticate host certificate: %v", err)
			}
			return nil
		},
		Timeout: 1 * time.Second,
	}

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return fmt.Errorf("failed to listen on a random port: %v", err)
	}
	defer listener.Close()

	errChan := make(chan error)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- fmt.Errorf("error accepting a connection to listner: %v", err)
			return
		}
		defer conn.Close()

		sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			errChan <- fmt.Errorf("error creating a new connection to SSH server: %v", err)
			return
		}
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)
		for newChannel := range chans {
			_, _, _ = newChannel.Accept()
		}
	}()

	go func() {
		if err := <-errChan; err != nil {
			fmt.Printf("Received error: %v\n", err)
		}
	}()

	conn, err := ssh.Dial("tcp", listener.Addr().String(), clientConfig)
	if err != nil {
		return fmt.Errorf("failed to dial the server: %v", err)
	}
	defer conn.Close()

	return nil
}
