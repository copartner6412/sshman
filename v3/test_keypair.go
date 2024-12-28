package sshman

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestKeyPair(keyPair *KeyPair) error {
	publicKey, privateKey, err := keyPair.Parse()
	if err != nil {
		return fmt.Errorf("error parsing key pair: %w", err)
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), publicKey.Marshal()) {
				return nil, fmt.Errorf("user authentication failed")
			}

			return &ssh.Permissions{}, nil
		},
	}

	serverConfig.AddHostKey(privateKey)

	clientConfig := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(privateKey)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if bytes.Equal(key.Marshal(), publicKey.Marshal()) {
				return fmt.Errorf("host athentication fialed")
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
