package sshman

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func IssueSSH(ca, keyPair KeyPair, certificate *ssh.Certificate, comment string) (SSH, error) {
	if err := validateIssueInput(ca, keyPair); err != nil {
		return SSH{}, fmt.Errorf("invalid input: %w", err)
	}

	_, caPrivateKey, err := ParseKeyPair(ca)
	if err != nil {
		return SSH{}, fmt.Errorf("error parsing CA: %w", err)
	}

	if err := certificate.SignCert(rand.Reader, caPrivateKey); err != nil {
		return SSH{}, fmt.Errorf("error signing certificate: %w", err)
	}

	result := SSH{
		PublicKey:          keyPair.PublicKey,
		PrivateKey:         keyPair.PrivateKey,
		Certificate:        ssh.MarshalAuthorizedKey(certificate),
		PrivateKeyPassword: keyPair.PrivateKeyPassword,
		NotBefore:          time.Unix(int64(certificate.ValidAfter), 0),
		NotAfter:           time.Unix(int64(certificate.ValidBefore), 0),
	}

	if _, _, _, err := ParseSSH(result); err != nil {
		return SSH{}, fmt.Errorf("generated invalid SSH asset: %w", err)
	}

	return result, nil
}

func validateIssueInput(ca, keyPair KeyPair) error {
	var errs []error

	if _, _, err := ParseKeyPair(ca); err != nil {
		errs = append(errs, fmt.Errorf("invalid CA: %w", err))
	}

	if _, _, err := ParseKeyPair(keyPair); err != nil {
		errs = append(errs, fmt.Errorf("invalid key pair: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
