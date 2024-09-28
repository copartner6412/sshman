package sshman

import (
	"crypto/rand"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func IssueSSH(ca, keyPair *KeyPair, CertificateRequest CertificateRequest) (*SSH, error) {
	if err := validateIssueSSHInput(ca, keyPair); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if err := CertificateRequest.SignCert(rand.Reader, caPrivateKey); err != nil {
		return nil, fmt.Errorf("error signing certificate: %w", err)
	}

	result := &SSH{
		PublicKey:          keyPair.PublicKey,
		PrivateKey:         keyPair.PrivateKey,
		Certificate:        ssh.MarshalAuthorizedKey(certificate),
		PrivateKeyPassword: keyPair.PrivateKeyPassword,
		NotBefore:          time.Unix(int64(certificate.ValidAfter), 0),
		NotAfter:           time.Unix(int64(certificate.ValidBefore), 0),
	}

	if _, _, _, err := result.Parse(); err != nil {
		return nil, fmt.Errorf("generated invalid SSH asset: %w", err)
	}

	return result, nil
}

func validateIssueSSHInput(ca, keyPair *KeyPair) error {
	var errs []error

	if _, _, err := keyPair.Parse(); err != nil {
		errs = append(errs, fmt.Errorf("invalid key pair: %w", err))
	}

	if _, _, err := ca.Parse(); err != nil {
		errs = append(errs, fmt.Errorf("invalid CA key pair: %w", err))
	}

	return nil
}
