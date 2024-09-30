package sshman_test

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/copartner6412/input/pseudorandom"
	"github.com/copartner6412/sshman"
)

func FuzzPackage(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		t.Parallel()
		r := rand.New(rand.NewPCG(seed1, seed2))

		subject, err := pseudorandomSubject(r)
		if err != nil {
			t.Fatalf("error generating pseudo-random subject: %v", err)
		}

		comment := sshman.CommentFor(subject)

		userInput, err := pseudorandomTestInput(r)
		if err != nil {
			t.Fatalf("error generating pseudo-random input for user: %v", err)
		}

		hostInput, err := pseudorandomTestInput(r)
		if err != nil {
			t.Fatalf("error generating pseudo-random input for host: %v", err)
		}

		reader := pseudorandom.New(r)

		generatedUserKeyPair, err := sshman.GenerateKeyPair(reader, userInput.algorithm, comment, userInput.password)
		if err != nil {
			t.Fatalf("error generating a pseudo-random key pair for user: %v", err)
		}

		generatedHostKeyPair, err := sshman.GenerateKeyPair(reader, hostInput.algorithm, comment, hostInput.password)
		if err != nil {
			t.Fatalf("error generating a pseudo-random key pair for host: %v", err)
		}

		userKeyPairDir := t.TempDir()
		hostKeyPairDir := t.TempDir()

		if err := generatedUserKeyPair.Save(userKeyPairDir); err != nil {
			t.Fatalf("error saving user key pair: %v", err)
		}

		if err := generatedHostKeyPair.Save(hostKeyPairDir); err != nil {
			t.Fatalf("error saving host key pair: %v", err)
		}

		userKeyPair, err := sshman.LoadKeyPair(userKeyPairDir, generatedUserKeyPair.PrivateKeyPassword)
		if err != nil {
			t.Fatalf("error loading user key pair: %v", err)
		}

		hostKeyPair, err := sshman.LoadKeyPair(hostKeyPairDir, generatedHostKeyPair.PrivateKeyPassword)
		if err != nil {
			t.Fatalf("error loading host key pair: %v", err)
		}

		if err := sshman.AddKeyToSSHAgent(userKeyPair); err != nil {
			t.Fatalf("error adding private key to SSH agent: %v", err)
		}

		sshDir := t.TempDir()
		clientConfigPath := filepath.Join(sshDir, "config")

		if _, err := os.Create(clientConfigPath); err != nil {
			t.Fatalf("error creating ssh client configuration file: %v", err)
		}

		var (
			privateKeyPath  string
			certificatePath string
		)

		switch userInput.algorithm {
		case sshman.AlgorithmUntyped, sshman.AlgorithmED25519:
			privateKeyPath = filepath.Join(userKeyPairDir, "id_ed25519")
		case sshman.AlgorithmECDSAP256, sshman.AlgorithmECDSAP384, sshman.AlgorithmECDSAP521:
			privateKeyPath = filepath.Join(userKeyPairDir, "id_ecdsa")
		case sshman.AlgorithmRSA2048, sshman.AlgorithmRSA4096:
			privateKeyPath = filepath.Join(userKeyPairDir, "id_rsa")
		}

		if _, err := sshman.AddHostToClientConfig(subject, clientConfigPath, privateKeyPath, ""); err != nil {
			t.Fatalf("error adding host to client config: %v", err)
		}

		userCertificateRequestBytes, err := sshman.NewCertificateRequest(subject, userKeyPair.PublicKey, sshman.UserCert, userInput.duration, nil, nil)
		if err != nil {
			t.Fatalf("error generating a request for user public key: %v", err)
		}

		hostCertificateRequestBytes, err := sshman.NewCertificateRequest(subject, hostKeyPair.PublicKey, sshman.HostCert, hostInput.duration, nil, nil)
		if err != nil {
			t.Fatalf("error generating a request for host public key: %v", err)
		}

		userCertificateRequest, err := sshman.ParseCertificateRequest(userCertificateRequestBytes)
		if err != nil {
			t.Fatalf("error parsing user certificate request: %v", err)
		}

		hostCertificateRequest, err := sshman.ParseCertificateRequest(hostCertificateRequestBytes)
		if err != nil {
			t.Fatalf("error parsing host certificate request: %v", err)
		}

		userCertificateBytes, err := userCertificateRequest.SignRequest(reader, userInput.ca)
		if err != nil {
			t.Fatalf("error signing user certificate request: %v", err)
		}

		hostCertificateBytes, err := hostCertificateRequest.SignRequest(reader, hostInput.ca)
		if err != nil {
			t.Fatalf("error signing host certificate request: %v", err)
		}

		generatedUserSSH, err := userKeyPair.NewSSH(userCertificateBytes)
		if err != nil {
			t.Fatalf("error creating new SSH user asset from user key pair and its certificate: %v", err)
		}

		generatedHostSSH, err := hostKeyPair.NewSSH(hostCertificateBytes)
		if err != nil {
			t.Fatalf("error creating new SSH host asset from host key pair and its certificate: %v", err)
		}

		userSSHDir := t.TempDir()
		hostSSHDir := t.TempDir()

		if err := generatedUserSSH.Save(userSSHDir); err != nil {
			t.Fatalf("error saving user SSH assets: %v", err)
		}

		if err := generatedHostSSH.Save(hostSSHDir); err != nil {
			t.Fatalf("error saving host SSH assets: %v", err)
		}

		userSSH, err := sshman.LoadSSH(userSSHDir, userInput.password)
		if err != nil {
			t.Fatalf("error saving user SSH assets: %v", err)
		}

		hostSSH, err := sshman.LoadSSH(hostSSHDir, hostInput.password)
		if err != nil {
			t.Fatalf("error saving host SSH assets: %v", err)
		}

		if err := sshman.AddKeyToSSHAgent(userSSH); err != nil {
			t.Fatalf("error adding SSH asset to SSH agent: %v", err)
		}

		switch userInput.algorithm {
		case sshman.AlgorithmUntyped, sshman.AlgorithmED25519:
			privateKeyPath = filepath.Join(userSSHDir, "id_ed25519")
			certificatePath = filepath.Join(userSSHDir, "id_ed25519-cert.pub")
		case sshman.AlgorithmECDSAP256, sshman.AlgorithmECDSAP384, sshman.AlgorithmECDSAP521:
			privateKeyPath = filepath.Join(userSSHDir, "id_ecdsa")
			certificatePath = filepath.Join(userSSHDir, "id_ecdsa-cert.pub")
		case sshman.AlgorithmRSA2048, sshman.AlgorithmRSA4096:
			privateKeyPath = filepath.Join(userSSHDir, "id_rsa")
			certificatePath = filepath.Join(userSSHDir, "id_rsa-cert.pub")
		}

		if _, err := sshman.AddHostToClientConfig(subject, clientConfigPath, privateKeyPath, certificatePath); err != nil {
			t.Fatalf("error adding host private key and certificate to client config: %v", err)
		}

		if err := sshman.DeleteHostFromClientConfig(subject, clientConfigPath); err != nil {
			t.Fatalf("error deleting host from client config: %v", err)
		}

		if err := sshman.TestSSH(userSSH, hostSSH, userInput.ca.PublicKey, hostInput.ca.PublicKey); err != nil {
			t.Fatalf("error testing SSH user and host: %v", err)
		}
	})
}
