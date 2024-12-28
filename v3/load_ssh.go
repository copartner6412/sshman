package sshman

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

var filenamesForLoadSSH = map[struct{ publicKey, privateKey, certificate string }]map[string]struct{}{
	{"id_ed25519.pub", "id_ed25519", "id_ed25519-cert.pub"}:          {ssh.KeyAlgoED25519: {}},
	{"id_ed25519_sk.pub", "id_ed25519_sk", "id_ed25519_sk-cert.pub"}: {ssh.KeyAlgoSKED25519: {}},
	{"id_ecdsa.pub", "id_ecdsa", "id_ecdsa-cert.pub"}:                {ssh.KeyAlgoECDSA521: {}, ssh.KeyAlgoECDSA384: {}, ssh.KeyAlgoECDSA256: {}},
	{"id_ecdsa_sk.pub", "id_ecdsa_sk", "id_ecdsa_sk-cert.pub"}:       {ssh.KeyAlgoSKECDSA256: {}},
	{"id_rsa.pub", "id_rsa", "id_rsa-cert.pub"}:                      {ssh.KeyAlgoRSA: {}},
}

var filenamesForPublicKey []string = []string{"id_ed25519.pub", "id_ed25519_sk.pub", "id_ecdsa.pub", "id_ecdsa_sk.pub", "id_rsa.pub"}
var filenamesForPrivateKey []string = []string{"id_ed25519", "id_ed25519_sk", "id_ecdsa", "id_ecdsa_sk", "id_rsa"}
var filenamesForCertificate []string = []string{"id_ed25519-cert.pub", "id_ed25519_sk-cert.pub", "id_ecdsa-cert.pub", "id_ecdsa_sk-cert.pub", "id_rsa-cert.pub"}

func LoadSSH(directory string, privateKeyPassword []byte) (*SSH, error) {
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
		errs = append(errs, errors.New("no public key file"))
	}

	if len(privateKeyFilenames) == 0 {
		errs = append(errs, errors.New("no private key file"))
	}

	if len(certificateFilenames) == 0 {
		errs = append(errs, errors.New("no certificate file"))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	if len(publicKeyFilenames) > 1 {
		errs = append(errs, errors.New("more than one public key file"))
	}

	if len(privateKeyFilenames) > 1 {
		errs = append(errs, errors.New("more than one private key file"))
	}

	if len(certificateFilenames) > 1 {
		errs = append(errs, errors.New("more than one certificate file"))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	nameSet := struct {
		publicKey   string
		privateKey  string
		certificate string
	}{
		publicKey:   publicKeyFilenames[0],
		privateKey:  privateKeyFilenames[0],
		certificate: certificateFilenames[0],
	}

	possibleAlgorithms, ok := filenamesForLoadSSH[nameSet]
	if !ok {
		return nil, fmt.Errorf("filenames mismatch, public key: %s, private key: %s, certificate: %s", nameSet.publicKey, nameSet.privateKey, nameSet.certificate)
	}

	files := map[string]string{
		"public key":  nameSet.publicKey,
		"private key": nameSet.privateKey,
		"certificate": nameSet.certificate,
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

	certificate, _, _, _, err := ssh.ParseAuthorizedKey(fileContents["certificate"])
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	certificateTypeAsserted := certificate.(*ssh.Certificate)

	result := &SSH{
		PublicKey:          fileContents["public key"],
		PrivateKey:         fileContents["private key"],
		Certificate:        fileContents["certificate"],
		PrivateKeyPassword: []byte(privateKeyPassword),
		NotBefore:          time.Unix(int64(certificateTypeAsserted.ValidAfter), 0),
		NotAfter:           time.Unix(int64(certificateTypeAsserted.ValidBefore), 0),
	}

	publicKey, _, _, err := result.Parse()
	if err != nil {
		return nil, fmt.Errorf("generated invalid SSH asset: %w", err)
	}

	if _, ok = possibleAlgorithms[publicKey.Type()]; !ok {
		return nil, fmt.Errorf("filename/algorithm mismatch, public key: %s, algorithm: %s", nameSet.publicKey, publicKey.Type())
	}

	return result, nil
}
