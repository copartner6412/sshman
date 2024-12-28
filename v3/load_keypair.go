package sshman

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

var filenamesForLoadKeyPair = map[struct{ publicKey, privateKey string }]map[string]struct{}{
	{"id_ed25519.pub", "id_ed25519"}:       {ssh.KeyAlgoED25519: {}},
	{"id_ed25519_sk.pub", "id_ed25519_sk"}: {ssh.KeyAlgoSKED25519: {}},
	{"id_ecdsa.pub", "id_ecdsa"}:           {ssh.KeyAlgoECDSA521: {}, ssh.KeyAlgoECDSA384: {}, ssh.KeyAlgoECDSA256: {}},
	{"id_ecdsa_sk.pub", "id_ecdsa_sk"}:     {ssh.KeyAlgoSKECDSA256: {}},
	{"id_rsa.pub", "id_rsa"}:               {ssh.KeyAlgoRSA: {}},
}

func LoadKeyPair(directory string, privateKeyPassword []byte) (*KeyPair, error) {
	if directory == "" {
		return nil, fmt.Errorf("empty directory path")
	}

	var errs []error
	var publicKeyFilenames []string
	var privateKeyFilenames []string
	var certificateFilenames []string

	for _, name := range filenamesForPublicKey {
		_, err := os.Stat(filepath.Join(directory, name))
		if !os.IsNotExist(err) {
			publicKeyFilenames = append(publicKeyFilenames, name)
		}
	}

	for _, name := range filenamesForPrivateKey {
		_, err := os.Stat(filepath.Join(directory, name))
		if !os.IsNotExist(err) {
			privateKeyFilenames = append(privateKeyFilenames, name)
		}
	}

	for _, name := range filenamesForCertificate {
		_, err := os.Stat(filepath.Join(directory, name))
		if !os.IsNotExist(err) {
			certificateFilenames = append(certificateFilenames, name)
		}
	}

	if len(publicKeyFilenames) == 0 {
		errs = append(errs, errors.New("no public key file exists"))
	}

	if len(privateKeyFilenames) == 0 {
		errs = append(errs, errors.New("no private key file exists"))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	if len(publicKeyFilenames) > 1 {
		errs = append(errs, errors.New("more than one public key file exist"))
	}

	if len(privateKeyFilenames) > 1 {
		errs = append(errs, errors.New("more than one private key file exist"))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	if len(certificateFilenames) > 0 {
		errs = append(errs, errors.New("at least one certificate file exists, please use sshman.ParseSSH"))
	}

	nameSet := struct {
		publicKey  string
		privateKey string
	}{
		publicKey:  publicKeyFilenames[0],
		privateKey: privateKeyFilenames[0],
	}

	possibleAlgorithms, ok := filenamesForLoadKeyPair[nameSet]
	if !ok {
		return nil, fmt.Errorf("filenames mismatch, public key: %s, private key: %s", nameSet.publicKey, nameSet.privateKey)
	}

	files := map[string]string{
		"public key":  nameSet.publicKey,
		"private key": nameSet.privateKey,
	}

	fileContents := make(map[string][]byte)

	for name, filename := range files {
		path := filepath.Join(directory, filename)

		file, err := os.Open(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("error opening %s: %w", path, err))
			continue
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			errs = append(errs, fmt.Errorf("error reading %s file: %w", name, err))
			continue
		}

		// Ensure consistent line endings (use LF) and remove any trailing whitespace.
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		data = bytes.TrimSpace(data)

		fileContents[name] = data
	}

	result := &KeyPair{
		PublicKey:          fileContents["public key"],
		PrivateKey:         fileContents["private key"],
		PrivateKeyPassword: []byte(privateKeyPassword),
	}

	publicKey, _, err := result.Parse()
	if err != nil {
		return nil, fmt.Errorf("generated invalid SSH asset: %w", err)
	}

	if _, ok = possibleAlgorithms[publicKey.Type()]; !ok {
		return nil, fmt.Errorf("filename/algorithm mismatch, public key: %s, algorithm: %s", nameSet.publicKey, publicKey.Type())
	}

	return result, nil
}
