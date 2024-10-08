package sshman

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHUser(sshAsset *SSH, caPublicKeyBytes []byte) error {
	var errs []error

	_, privateKey, certificate, err := sshAsset.Parse()
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing user SSH asset: %w", err))
	}

	caPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(caPublicKeyBytes)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing CA public key: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid input: %w", errors.Join(errs...))
	}

	hostKeyPair, err := GenerateKeyPair(rand.Reader, AlgorithmED25519, "", nil)
	if err != nil {
		return fmt.Errorf("error generating a random key pair for test SSH server: %w", err)
	}

	_, hostPrivateKey, err := hostKeyPair.Parse()
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

			err = userCertChecker.CheckCert(certificate.ValidPrincipals[0], key.(*ssh.Certificate))
			if err != nil {
				return nil, fmt.Errorf("invalid certificate: %w", err)
			}

			return permissions, nil
		},
	}

	serverConfig.AddHostKey(hostPrivateKey)

	userCertPrivateKey, err := ssh.NewCertSigner(certificate, privateKey)
	if err != nil {
		return fmt.Errorf("error creating a ssh.CertSigner for user: %v", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            certificate.ValidPrincipals[0],
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(userCertPrivateKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         1 * time.Second,
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
