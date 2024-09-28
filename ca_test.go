package sshman_test

import (
	"math/rand/v2"
	"testing"

	"github.com/copartner6412/sshman"
)

func FuzzCA(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		t.Parallel()

		r := rand.New(rand.NewPCG(seed1, seed2))

		input, err := pseudorandomInputForGenerateSSH(r)
		if err != nil {
			t.Fatalf("error generating pseudo-random input for user: %v", err)
		}

		keyPair, err := sshman.GenerateKeyPair(input.algorithm, input.comment, input.password)
		if err != nil {
			t.Fatalf("error generating a random key pair: %v", err)
		}

		requestBytes, err := sshman.NewCertificateRequest(input.subject, keyPair.PublicKey, sshman.UserCert, input.duration)
		if err != nil {
			t.Fatalf("error generating a request for public key: %v", err)
		}

		certificateBytes, err := sshman.SignCertificateRequest(input.ca, requestBytes)
		if err != nil {
			t.Fatalf("error signing request: %v", err)
		}

		sshAsset, err := sshman.NewSSHFromKeyPair(keyPair, certificateBytes)
		if err != nil {
			t.Fatalf("error creating SSH from key pair and signed certificate: %v", err)
		}

		if err := sshman.SSHUserWorks(sshAsset, input.ca.PublicKey); err != nil {
			t.Fatalf("generated SSH asset doesn't work: %v", err)
		}
	})
}
