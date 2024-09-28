package sshman

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSH struct {
	PublicKey          []byte
	PrivateKey         []byte
	Certificate        []byte
	PrivateKeyPassword []byte
	NotBefore          time.Time
	NotAfter           time.Time
}

var filenamesForSave map[string]struct {
	publicKey, privateKey, certificate string
} = map[string]struct {
	publicKey   string
	privateKey  string
	certificate string
}{
	ssh.KeyAlgoED25519:    {"id_ed25519.pub", "id_ed25519", "id_ed25519-cert.pub"},
	ssh.KeyAlgoSKED25519:  {"id_ed25519_sk.pub", "id_ed25519_sk", "id_ed25519_sk-cert.pub"},
	ssh.KeyAlgoECDSA521:   {"id_ecdsa.pub", "id_ecdsa", "id_ecdsa-cert.pub"},
	ssh.KeyAlgoECDSA384:   {"id_ecdsa.pub", "id_ecdsa", "id_ecdsa-cert.pub"},
	ssh.KeyAlgoECDSA256:   {"id_ecdsa.pub", "id_ecdsa", "id_ecdsa-cert.pub"},
	ssh.KeyAlgoSKECDSA256: {"id_ecdsa_sk.pub", "id_ecdsa_sk", "id_ecdsa_sk-cert.pub"},
	ssh.KeyAlgoRSA:        {"id_rsa.pub", "id_rsa", "id_rsa-cert.pub"},
}

func (s *SSH) Destroy() {
	s.PublicKey = nil
	s.PrivateKey = nil
	s.Certificate = nil
	s.PrivateKeyPassword = nil
	s.NotBefore = time.Time{}
	s.NotAfter = time.Time{}
}

func (s *SSH) IsZero() bool {
	return len(s.PublicKey) == 0 &&
		len(s.PrivateKey) == 0 &&
		len(s.PrivateKeyPassword) == 0 &&
		len(s.Certificate) == 0 &&
		s.NotBefore.IsZero() &&
		s.NotAfter.IsZero()
}

func (s *SSH) Equal(sshAsset SSH) bool {
	return bytes.Equal(s.PublicKey, sshAsset.PublicKey) &&
		bytes.Equal(s.PrivateKey, sshAsset.PrivateKey) &&
		bytes.Equal(s.Certificate, sshAsset.Certificate) &&
		bytes.Equal(s.PrivateKeyPassword, sshAsset.PrivateKeyPassword) &&
		s.NotBefore.Equal(sshAsset.NotBefore) &&
		s.NotBefore.Equal(sshAsset.NotAfter)
}

func (s *SSH) Parse() (publicKey ssh.PublicKey, privateKey ssh.Signer, certificate *ssh.Certificate, err error) {
	var errs []error
	var ok bool

	if s.PublicKey == nil {
		errs = append(errs, fmt.Errorf("nil public key"))
	}

	if s.PrivateKey == nil {
		errs = append(errs, fmt.Errorf("nil private key"))
	}

	if s.Certificate == nil {
		errs = append(errs, fmt.Errorf("nil pointer to certificate"))
	}

	if len(errs) > 0 {
		return nil, nil, nil, errors.Join(errs...)
	}

	publicKey, _, _, _, err = ssh.ParseAuthorizedKey(s.PublicKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing public key: %w", err))
	}

	if s.PrivateKeyPassword == nil {
		privateKey, err = ssh.ParsePrivateKey(s.PrivateKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing private key with password: %w", err))
		}
	} else {
		privateKey, err = ssh.ParsePrivateKeyWithPassphrase(s.PrivateKey, s.PrivateKeyPassword)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing private key: %w", err))
		}
	}

	certificateNotTypeAsserted, _, _, _, err := ssh.ParseAuthorizedKey(s.Certificate)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing certficiate: %w", err))
	}

	if len(errs) > 0 {
		return nil, nil, nil, errors.Join(errs...)
	}

	if certificate, ok = certificateNotTypeAsserted.(*ssh.Certificate); !ok {
		return nil, nil, nil, fmt.Errorf("invalid type for certificate: %w", err)
	}

	if !areKeysMatched(certificate.Key, privateKey) {
		return nil, nil, nil, errors.New("key pair mismatch")
	}

	if !arePublicKeyAndCertificateMatched(certificate, publicKey) {
		return nil, nil, nil, errors.New("certificate/public-key mismatch")
	}

	return publicKey, privateKey, certificate, nil
}

func arePublicKeyAndCertificateMatched(certificate *ssh.Certificate, publicKey ssh.PublicKey) bool {
	derivedPublicKey := certificate.Key

	if publicKey.Type() != derivedPublicKey.Type() {
		return false
	}

	return bytes.Equal(publicKey.Marshal(), derivedPublicKey.Marshal())
}

func (s *SSH) Save(directory string) error {
	keyType, err := validateSaveSSHInput(s, directory)
	if err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	// Define files with their attributes.
	files := map[string]struct {
		filename   string
		data       []byte
		permission os.FileMode
	}{
		"public key":  {filename: filenamesForSave[keyType].publicKey, data: s.PublicKey, permission: os.FileMode(0644)},
		"private key": {filename: filenamesForSave[keyType].privateKey, data: s.PrivateKey, permission: os.FileMode(0600)},
		"certificate": {filename: filenamesForSave[keyType].certificate, data: s.Certificate, permission: os.FileMode(0644)},
	}

	// Write each file.
	var errs []error
	for name, file := range files {
		if err := writeBytesToFile(directory, name, file.filename, file.data, file.permission); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func validateSaveSSHInput(sshAsset *SSH, directory string) (string, error) {
	var errs []error
	if directory == "" {
		errs = append(errs, fmt.Errorf("empty directory path"))
	}

	publicKey, _, _, err := sshAsset.Parse()
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid SSH: %w", err))
	}

	if len(errs) > 0 {
		return "", errors.Join(errs...)
	}

	return publicKey.Type(), nil
}

func (s *SSH) Type() string {
	publicKey, _, _, err := s.Parse()
	if err != nil {
		return ""
	}

	return publicKey.Type()
}
