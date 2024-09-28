package sshman

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSH(sshUser, sshHost *SSH, userCAPublicKeyBytes, hostCAPublicKeyBytes []byte) error {
	var errs []error

	_, userPrivateKey, userCertificate, err := sshUser.Parse()
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing user SSH asset: %w", err))
	}

	_, hostPrivateKey, hostCertificate, err := sshHost.Parse()
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing host SSH asset: %w", err))
	}

	userCAPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(userCAPublicKeyBytes)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing user CA public key: %w", err))
	}

	hostCAPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(hostCAPublicKeyBytes)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing host CA public key: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid input: %w", errors.Join(errs...))
	}

	userCertChecker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), userCAPublicKey.Marshal())
		},
	}

	hostCertPrivateKey, err := ssh.NewCertSigner(hostCertificate, hostPrivateKey)
	if err != nil {
		return fmt.Errorf("error creating a ssh.CertSigner for host: %v", err)
	}

	// Create an ssh.ServerConfig and set the PublicKeyCallback
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			permissions, err := userCertChecker.Authenticate(conn, key)
			if err != nil {
				return nil, fmt.Errorf("failed to authenticate user certificate: %v", err)
			}

			err = userCertChecker.CheckCert(userCertificate.ValidPrincipals[0], key.(*ssh.Certificate))
			if err != nil {
				return nil, fmt.Errorf("invalid user certificate: %v", err)
			}

			return permissions, nil
		},
	}

	serverConfig.AddHostKey(hostCertPrivateKey)

	hostCertChecker := ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			return bytes.Equal(auth.Marshal(), hostCAPublicKey.Marshal())
		},
	}

	userCertPrivateKey, err := ssh.NewCertSigner(userCertificate, userPrivateKey)
	if err != nil {
		return fmt.Errorf("error creating a ssh.CertSigner for user: %v", err)
	}

	clientConfig := &ssh.ClientConfig{
		User: userCertificate.ValidPrincipals[0],
		Auth: []ssh.AuthMethod{ssh.PublicKeys(userCertPrivateKey)},
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

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			return
		}
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)
		for newChannel := range chans {
			_, _, _ = newChannel.Accept()
		}
	}()
	wg.Wait()

	conn, err := ssh.Dial("tcp", listener.Addr().String(), clientConfig)
	if err != nil {
		return fmt.Errorf("failed to dial the server: %v", err)
	}
	defer conn.Close()

	return nil
}
