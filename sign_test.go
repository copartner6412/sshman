package sshman_test

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/copartner6412/sshman"
	"golang.org/x/crypto/ssh"
)

func FuzzSign(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		t.Parallel()

		r := rand.New(rand.NewPCG(seed1, seed2))

		userInput, err := pseudorandomInputForGenerateSSH(r)
		if err != nil {
			t.Fatalf("error generating pseudo-random input for user: %v", err)
		}

		hostInput, err := pseudorandomInputForGenerateSSH(r)
		if err != nil {
			t.Fatalf("error generating pseudo-random input for host: %v", err)
		}

		userCAPublicKey, _, err := sshman.ParseKeyPair(userInput.ca)
		if err != nil {
			t.Fatalf("error parsing user CA key pair: %v", err)
		}

		hostCAPublicKey, _, err := sshman.ParseKeyPair(hostInput.ca)
		if err != nil {
			t.Fatalf("error parsing host CA key pair: %v", err)
		}

		userKeyPair, err := sshman.GenerateKeyPair(userInput.algorithm, userInput.comment, userInput.password)
		if err != nil {
			t.Fatalf("error generating user key pair: %v", err)
		}

		userCertificateBytes, err := sshman.Sign(userInput.subject, userInput.ca, userKeyPair.PublicKey, sshman.UserCert, userInput.duration)
		if err != nil {
			t.Fatalf("error signing user public key: %v", err)
		}

		hostKeyPair, err := sshman.GenerateKeyPair(hostInput.algorithm, hostInput.comment, hostInput.password)
		if err != nil {
			t.Fatalf("error generating host key pair: %v", err)
		}

		hostCertificateBytes, err := sshman.Sign(hostInput.subject, hostInput.ca, hostKeyPair.PublicKey, sshman.HostCert, hostInput.duration)
		if err != nil {
			t.Fatalf("error siging host public key: %v", err)
		}

		userSSHAsset := sshman.SSH{
			PublicKey:          userKeyPair.PublicKey,
			PrivateKey:         userKeyPair.PrivateKey,
			Certificate:        userCertificateBytes,
			PrivateKeyPassword: userKeyPair.PrivateKeyPassword,
			NotBefore:          time.Now(),
			NotAfter:           time.Now().Add(userInput.duration),
		}

		hostSSHAsset := sshman.SSH{
			PublicKey:          hostKeyPair.PublicKey,
			PrivateKey:         hostKeyPair.PrivateKey,
			Certificate:        hostCertificateBytes,
			PrivateKeyPassword: hostKeyPair.PrivateKeyPassword,
			NotBefore:          time.Now(),
			NotAfter:           time.Now().Add(hostInput.duration),
		}

		_, userPrivateKey, userCertificate, err := sshman.ParseSSH(userSSHAsset)
		if err != nil {
			t.Fatalf("error parsing user SSH asset: %v", err)
		}

		_, hostPrivateKey, hostCertificate, err := sshman.ParseSSH(hostSSHAsset)
		if err != nil {
			t.Fatalf("error parsing host SSH asset: %v", err)
		}

		userCertChecker := ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				return bytes.Equal(auth.Marshal(), userCAPublicKey.Marshal())
			},
		}

		hostCertPrivateKey, err := ssh.NewCertSigner(hostCertificate, hostPrivateKey)
		if err != nil {
			t.Fatalf("error creating a ssh.CertSigner for host: %v", err)
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
			t.Fatalf("error creating a ssh.CertSigner for user: %v", err)
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
			t.Fatalf("failed to listen on a random port: %v", err)
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

		// Step 5: Create a client and check if it can connect to the server
		conn, err := ssh.Dial("tcp", listener.Addr().String(), clientConfig)
		if err != nil {
			t.Errorf("failed to dial the server: %v", err)
			return
		}
		defer conn.Close()
	})
}
