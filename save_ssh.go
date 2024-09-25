package sshman

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

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

func SaveSSH(sshAsset SSH, directory string) error {
	keyType, err := validateSaveSSHInput(sshAsset, directory)
	if err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	// Define files with their attributes.
	files := map[string]struct {
		filename   string
		data       []byte
		permission os.FileMode
	}{
		"public key":  {filename: filenamesForSave[keyType].publicKey, data: sshAsset.PublicKey, permission: os.FileMode(0644)},
		"private key": {filename: filenamesForSave[keyType].privateKey, data: sshAsset.PrivateKey, permission: os.FileMode(0600)},
		"certificate": {filename: filenamesForSave[keyType].certificate, data: sshAsset.Certificate, permission: os.FileMode(0644)},
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

func validateSaveSSHInput(sshAsset SSH, directory string) (string, error) {
	var errs []error
	if directory == "" {
		errs = append(errs, fmt.Errorf("empty directory path"))
	}

	publicKey, _, _, err := ParseSSH(sshAsset)
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid SSH: %w", err))
	}

	if len(errs) > 0 {
		return "", errors.Join(errs...)
	}

	return publicKey.Type(), nil
}
