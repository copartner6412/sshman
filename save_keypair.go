package sshman

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func SaveKeyPair(keyPair KeyPair, directory string) error {
	keyType, err := validateSaveKeyPairInput(keyPair, directory)
	if err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	files := map[string]struct {
		filename   string
		data       []byte
		permission os.FileMode
	}{
		"public key":  {filename: filenamesForSave[keyType].publicKey, data: keyPair.PublicKey, permission: os.FileMode(0600)},
		"private key": {filename: filenamesForSave[keyType].privateKey, data: keyPair.PrivateKey, permission: os.FileMode(0644)},
	}

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

func validateSaveKeyPairInput(keypair KeyPair, directory string) (string, error) {
	var errs []error
	if directory == "" {
		errs = append(errs, fmt.Errorf("empty directory path"))
	}

	publicKey, _, err := ParseKeyPair(keypair)
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid key pair: %w", err))
	}

	if len(errs) > 0 {
		return "", errors.Join(errs...)
	}

	return publicKey.Type(), nil
}

func writeBytesToFile(dir, name, filename string, data []byte, permission os.FileMode) error {
	path := filepath.Join(dir, filename)

	// Ensure consistent line endings (use LF) and remove any trailing whitespace.
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.TrimSpace(data)

	// Open file with O_SYNC flag
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, permission)
	if err != nil {
		return fmt.Errorf("error opening %s for writing: %w", name, err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("error writing %s: %w", name, err)
	}

	return nil
}
