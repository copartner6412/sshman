package sshman

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func IssueSSH(ca KeyPair, publicKey ssh.PublicKey, privateKey ssh.Signer, certificate *ssh.Certificate, comment, password string) (SSH, error) {
	if err := validateIssueInput(ca, publicKey, privateKey, certificate); err != nil {
		return SSH{}, fmt.Errorf("invalid input: %w", err)
	}

	_, caPrivateKey, err := ParseKeyPair(ca)
	if err != nil {
		return SSH{}, fmt.Errorf("error parsing CA: %w", err)
	}

	if err := certificate.SignCert(rand.Reader, caPrivateKey); err != nil {
		return SSH{}, fmt.Errorf("error signing certificate: %w", err)
	}

	privateKeyPEMBytes, err := encodePrivateKeyToPEMBytes(privateKey, comment, password)
	if err != nil {
		return SSH{}, fmt.Errorf("error PEM-encoding private key: %w", err)
	}

	result := SSH{
		PublicKey:          ssh.MarshalAuthorizedKey(publicKey),
		PrivateKey:         privateKeyPEMBytes,
		Certificate:        ssh.MarshalAuthorizedKey(certificate),
		PrivateKeyPassword: []byte(password),
		NotBefore:          time.Unix(int64(certificate.ValidAfter), 0),
		NotAfter:           time.Unix(int64(certificate.ValidBefore), 0),
	}

	if _, _, _, err := ParseSSH(result); err != nil {
		return SSH{}, fmt.Errorf("generated invalid SSH asset: %w", err)
	}

	return result, nil
}

func validateIssueInput(ca KeyPair, publicKey ssh.PublicKey, privateKey ssh.Signer, certificate *ssh.Certificate) error {
	var errs []error

	if _, _, err := ParseKeyPair(ca); err != nil {
		errs = append(errs, fmt.Errorf("invalid CA: %w", err))
	}

	if !areKeysMatched(publicKey, privateKey) {
		errs = append(errs, fmt.Errorf("key pair mismatch"))
	}

	if !arePublicKeyAndCertificateMatched(certificate, publicKey) {
		errs = append(errs, fmt.Errorf("certificate/public-key mismatch"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
