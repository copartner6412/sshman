package sshman

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func SSHUserWorks(sshAsset SSH, caPublicKey ssh.PublicKey) error {
	_, userPrivateKey, userCertificate, err := ParseSSH(sshAsset)
	if err != nil {
		return fmt.Errorf("error parsing user SSH asset: %w", err)
	}

	hostKeyPair, err := GenerateKeyPair(AlgorithmED25519, "", "")
	if err != nil {
		return fmt.Errorf("error generating a random key pair for test SSH server: %w", err)
	}

	_, hostPrivateKey, err := ParseKeyPair(hostKeyPair)
	if err != nil {
		return fmt.Errorf("error parsing host key pair: %w", err)
	}

	userCertChecker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caPublicKey.Marshal())
		},
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			permissions, err := userCertChecker.Authenticate(conn, key)
			if err != nil {
				return nil, fmt.Errorf("error authenticating user certificate: %v", err)
			}
			err = userCertChecker.CheckCert(userCertificate.ValidPrincipals[0], key.(*ssh.Certificate))
			if err != nil {
				return nil, fmt.Errorf("invalid certificate: %w", err)
			}
			return permissions, nil
		},
	}

	serverConfig.AddHostKey(hostPrivateKey)

	clientConfig := &ssh.ClientConfig{
		User:    userCertificate.ValidPrincipals[0],
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(userPrivateKey)},
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

func SSHHostWorks(sshAsset SSH, caPublicKey ssh.PublicKey) error {
	_, hostPrivateKey, hostCertificate, err := ParseSSH(sshAsset)
	if err != nil {
		return fmt.Errorf("error parsing host SSH asset: %w", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != "password" {
				return nil, errors.New("wrong password")
			}

			return &ssh.Permissions{}, nil
		},
	}

	serverConfig.AddHostKey(hostPrivateKey)

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
