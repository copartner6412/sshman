package sshman_test

import (
	cryptorand "crypto/rand"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/copartner6412/input/pseudorandom"
	"github.com/copartner6412/sshman"
)

func FuzzPackage(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		t.Parallel()
		r := rand.New(rand.NewPCG(seed1, seed2))

		userInput, err := pseudorandomTestInput(r)
		if err != nil {
			t.Fatalf("error generating pseudorandom test input for user: %v", err)
		}

		hostInput, err := pseudorandomTestInput(r)
		if err != nil {
			t.Fatalf("error generating pseudorandom test input for host: %v", err)
		}

		generatedUserKeyPair, err := sshman.GenerateKeyPair(cryptorand.Reader, userInput.algorithm, userInput.comment, userInput.password)
		if err != nil {
			t.Fatalf("error generating a pseudo-random key pair for user: %v", err)
		}

		generatedHostKeyPair, err := sshman.GenerateKeyPair(cryptorand.Reader, hostInput.algorithm, hostInput.comment, hostInput.password)
		if err != nil {
			t.Fatalf("error generating a pseudo-random key pair for host: %v", err)
		}

		userSSHKeyPairDir := t.TempDir()
		hostSSHKeyPairDir := t.TempDir()

		if err := generatedUserKeyPair.Save(userSSHKeyPairDir); err != nil {
			t.Fatalf("error saving user key pair: %v", err)
		}

		if err := generatedHostKeyPair.Save(hostSSHKeyPairDir); err != nil {
			t.Fatalf("error saving host key pair: %v", err)
		}

		userSSHKeyPair, err := sshman.LoadKeyPair(userSSHKeyPairDir, generatedUserKeyPair.PrivateKeyPassword)
		if err != nil {
			t.Fatalf("error loading user ssh key pair: %v", err)
		}

		hostSSHKeyPair, err := sshman.LoadKeyPair(hostSSHKeyPairDir, generatedHostKeyPair.PrivateKeyPassword)
		if err != nil {
			t.Fatalf("error loading host ssh key pair: %v", err)
		}

		userAuthenticationKeyPair, err := sshman.GenerateKeyPair(cryptorand.Reader, hostInput.algorithm, userInput.comment, userInput.password)
		if err != nil {
			t.Fatalf("error loading user authenticationkey pair: %v", err)
		}

		hostAuthenticationKeyPair, err := sshman.GenerateKeyPair(cryptorand.Reader, userInput.algorithm, hostInput.comment, hostInput.password)
		if err != nil {
			t.Fatalf("error loading user authenticationkey pair: %v", err)
		}

		if err := sshman.AddKeyToSSHAgent(userSSHKeyPair); err != nil {
			t.Fatalf("error adding private key to SSH agent: %v", err)
		}

		sshDir := t.TempDir()
		clientConfigPath := filepath.Join(sshDir, "config")

		if _, err := os.Create(clientConfigPath); err != nil {
			t.Fatalf("error creating ssh client configuration file: %v", err)
		}

		var privateKeyPath, certificatePath string

		etcDir := t.TempDir()
		authorizedHostsFilePath := filepath.Join(etcDir, "authorized_hosts.json")
		authorizedRequestersFilePath := filepath.Join(etcDir, "authorized_requesters.json")
		certificatePoliciesFilePath := filepath.Join(etcDir, "certificate_policies.json")
		etcFiles := []string{authorizedHostsFilePath, authorizedRequestersFilePath, certificatePoliciesFilePath}
		for _, file := range etcFiles {
			if err := os.WriteFile(file, []byte("[]"), 0600); err != nil {
				t.Fatalf("error creating %s: %v", filepath.Base(file), err)
			}
		}

		allRequesters, err := sshman.LoadCertificateRequesters(authorizedRequestersFilePath)
		if err != nil {
			t.Fatalf("error loading authorized requesters: %v", err)
		}

		allRequesters, err = sshman.AddCertificateRequester(allRequesters, sshman.CertificateRequester{
			ID:                      "requester_1",
			Name:                    "user requester",
			AuthenticationPublicKey: userAuthenticationKeyPair.PublicKey,
			Type:                    sshman.UserCert.String(),
		})
		if err != nil {
			t.Fatalf("error adding user requester to authorized requesters: %v", err)
		}

		allRequesters, err = sshman.AddCertificateRequester(allRequesters, sshman.CertificateRequester{
			ID:                      "requester_2",
			Name:                    "host requester",
			AuthenticationPublicKey: hostAuthenticationKeyPair.PublicKey,
			Type:                    sshman.HostCert.String(),
		})
		if err != nil {
			t.Fatalf("error adding host requester to authorized requesters: %v", err)
		}

		if err := sshman.SaveCertificateRequesters(authorizedRequestersFilePath, allRequesters); err != nil {
			t.Fatalf("error saving authorized requesters file: %v", err)
		}

		data, _ := os.ReadFile(authorizedRequestersFilePath)
		t.Log(string(data))

		allHosts, err := sshman.LoadHosts(authorizedHostsFilePath)
		if err != nil {
			t.Fatalf("error loading authorized hosts file: %v", err)
		}

		port := pseudorandom.PortPrivate(r)

		allHosts, err = sshman.AddHost(allHosts, sshman.Host{
			ID:            "host_1",
			SSHAddresses:  []string{"127.0.0.1"},
			SSHPublicKeys: [][]byte{hostSSHKeyPair.PublicKey},
			SSHUsers:      []string{"sshuser"},
			SSHPort:       port,
		})
		if err != nil {
			t.Fatalf("error adding host: %v", err)
		}

		if err := sshman.SaveHosts(authorizedHostsFilePath, allHosts); err != nil {
			t.Fatalf("error saving authorized hosts file: %v", err)
		}

		allPolicies, err := sshman.LoadCertificatePolicies(certificatePoliciesFilePath)
		if err != nil {
			t.Fatalf("error loading certificate policies: %v", err)
		}

		allPolicies, err = sshman.AddCertificatePolicy(allPolicies, sshman.CertificatePolicy{
			ID:          "policy_1",
			RequesterID: "requester_1",
			Type:        sshman.UserCert.String(),
			ValidUser:   "sshuser",
			ValidHostID: "host_1",
			ValidAfter:  time.Now(),
			ValidBefore: time.Now().Add(userInput.duration),
			CriticalOptions: map[string]string{
				"source-address": "127.0.0.1",
			},
		})
		if err != nil {
			t.Fatalf("error adding user certificate policy: %v", err)
		}

		allPolicies, err = sshman.AddCertificatePolicy(allPolicies, sshman.CertificatePolicy{
			ID:          "policy_2",
			RequesterID: "requester_2",
			Type:        sshman.HostCert.String(),
			ValidHostID: "host_1",
			ValidAfter:  time.Now(),
			ValidBefore: time.Now().Add(hostInput.duration),
		})
		if err != nil {
			t.Fatalf("error adding host certificate policy: %v", err)
		}

		if err := sshman.SaveCertificatePolicies(certificatePoliciesFilePath, allPolicies); err != nil {
			t.Fatalf("error saving certificate policies: %v", err)
		}

		userCertificateRequest := sshman.CertificateRequest{
			RequesterID:        "requester_1",
			RequesterPublicKey: userSSHKeyPair.PublicKey,
			RequestedUser:      "sshuser",
			RequestedHost:      "host_1",
			CertificateType:    sshman.UserCert,
		}

		hostCertificateRequest := sshman.CertificateRequest{
			RequesterID:        "requester_2",
			RequesterPublicKey: hostSSHKeyPair.PublicKey,
			RequestedHost:      "host_1",
			CertificateType:    sshman.HostCert,
		}

		if err := userCertificateRequest.Sign(cryptorand.Reader, userAuthenticationKeyPair); err != nil {
			t.Fatalf("error signing user certificate request: %v", err)
		}

		if err := hostCertificateRequest.Sign(cryptorand.Reader, hostAuthenticationKeyPair); err != nil {
			t.Fatalf("error signing host certificate request: %v", err)
		}

		userCertificateRequestBytes, err := userCertificateRequest.Marshal()
		if err != nil {
			t.Fatalf("error marshaling user certificate request: %v", err)
		}

		hostCertificateRequestBytes, err := hostCertificateRequest.Marshal()
		if err != nil {
			t.Fatalf("error marshaling host certificate request: %v", err)
		}

		data, _ = os.ReadFile(authorizedRequestersFilePath)
		t.Log(string(data))

		data, _ = os.ReadFile(certificatePoliciesFilePath)
		t.Log(string(data))

		userCertificates, err := sshman.CreateCertificate(userInput.ca, userCertificateRequestBytes, authorizedRequestersFilePath, authorizedHostsFilePath, certificatePoliciesFilePath)
		if err != nil {
			t.Fatalf("error creating user certificate: %v", err)
		}

		hostCertificates, err := sshman.CreateCertificate(hostInput.ca, hostCertificateRequestBytes, authorizedRequestersFilePath, authorizedHostsFilePath, certificatePoliciesFilePath)
		if err != nil {
			t.Fatalf("error creating host certificate: %v", err)
		}

		generatedUserSSH, err := userSSHKeyPair.NewSSH(userCertificates[0])
		if err != nil {
			t.Fatalf("error creating new SSH user asset from user key pair and its certificate: %v", err)
		}

		generatedHostSSH, err := hostSSHKeyPair.NewSSH(hostCertificates[0])
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

		allBlocks, err := sshman.LoadClientConfigBlocks(clientConfigPath)
		if err != nil {
			t.Fatalf("error loading client config block: %v", err)
		}

		if _, err := sshman.AddClientConfigBlock(allBlocks, sshman.ClientConfigBlock{
			ID:              "host_1",
			User:            "sshuser",
			Address:         "127.0.0.1",
			Port:            port,
			IdentityFile:    privateKeyPath,
			IdentitiesOnly:  true,
			CertificateFile: certificatePath,
		}); err != nil {
			t.Fatalf("error adding host private key and certificate to client config: %v", err)
		}

		if err := sshman.TestSSH(userSSH, hostSSH, userInput.ca.PublicKey, hostInput.ca.PublicKey); err != nil {
			t.Fatalf("error testing SSH user and host: %v", err)
		}
	})
}
