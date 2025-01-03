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

type KeyPair struct {
	PublicKey          []byte
	PrivateKey         []byte
	PrivateKeyPassword []byte
}

func (k *KeyPair) Destroy() {
	k.PublicKey = nil
	k.PrivateKey = nil
	k.PrivateKeyPassword = nil
}

func (k *KeyPair) IsZero() bool {
	return len(k.PublicKey) == 0 &&
		len(k.PrivateKey) == 0 &&
		len(k.PrivateKeyPassword) == 0
}

func (k *KeyPair) Equal(keyPair KeyPair) bool {
	return bytes.Equal(k.PublicKey, keyPair.PublicKey) &&
		bytes.Equal(k.PrivateKey, k.PrivateKey) &&
		bytes.Equal(k.PrivateKeyPassword, keyPair.PrivateKeyPassword)
}

func (k *KeyPair) Type() string {
	publicKey, _, err := k.Parse()
	if err != nil {
		return ""
	}

	return publicKey.Type()
}

func (k *KeyPair) Parse() (publicKey ssh.PublicKey, privateKey ssh.Signer, err error) {
	var errs []error

	if k.PublicKey == nil {
		errs = append(errs, fmt.Errorf("nil public key"))
	}

	if k.PrivateKey == nil {
		errs = append(errs, fmt.Errorf("nil private key"))
	}

	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}

	publicKey, _, _, _, err = ssh.ParseAuthorizedKey(k.PublicKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing public key: %w", err))
	}

	if k.PrivateKeyPassword != nil {
		privateKey, err = ssh.ParsePrivateKeyWithPassphrase(k.PrivateKey, k.PrivateKeyPassword)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing private key: %w", err))
		}
	} else {
		privateKey, err = ssh.ParsePrivateKey(k.PrivateKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing private key with password: %w", err))
		}
	}

	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}

	if !arePublicAndPrivateKeysMatched(publicKey, privateKey) {
		return nil, nil, errors.New("key pair mismatch")
	}

	return publicKey, privateKey, nil
}

func arePublicAndPrivateKeysMatched(publicKey ssh.PublicKey, privateKey ssh.Signer) bool {
	derivedPublicKey := privateKey.PublicKey()

	// Compare the key types
	if publicKey.Type() != derivedPublicKey.Type() {
		return false
	}

	// Compare the marshaled forms of the public keys
	return bytes.Equal(publicKey.Marshal(), derivedPublicKey.Marshal())
}

func (k *KeyPair) Save(directory string) error {
	if directory == "" {
		return fmt.Errorf("empty directory path")
	}

	keyType := k.Type()

	files := map[string]struct {
		filename   string
		data       []byte
		permission os.FileMode
	}{
		"public key":  {filename: filenamesForSave[keyType].publicKey, data: k.PublicKey, permission: os.FileMode(0600)},
		"private key": {filename: filenamesForSave[keyType].privateKey, data: k.PrivateKey, permission: os.FileMode(0644)},
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

func writeBytesToFile(dir, name, filename string, data []byte, permission os.FileMode) error {
	path := filepath.Join(dir, filename)

	// Ensure consistent line endings (use LF) and remove any trailing whitespace.
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.TrimSpace(data)

	if err := os.MkdirAll(dir, 700); err != nil {
		return fmt.Errorf("error creating directory %s: %w", dir, err)
	}

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

func (k *KeyPair) NewSSH(certificateBytes []byte) (*SSH, error) {
	if err := validateNewSSHInput(k, certificateBytes); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	cert, _, _, _, err := ssh.ParseAuthorizedKey(certificateBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	certificate := cert.(*ssh.Certificate)

	result := &SSH{
		PublicKey:          k.PublicKey,
		PrivateKey:         k.PrivateKey,
		Certificate:        certificateBytes,
		PrivateKeyPassword: k.PrivateKeyPassword,
		NotBefore:          time.Unix(int64(certificate.ValidAfter), 0),
		NotAfter:           time.Unix(int64(certificate.ValidBefore), 0),
	}

	if _, _, _, err := result.Parse(); err != nil {
		return nil, fmt.Errorf("generated invalid SSH")
	}

	return result, nil
}

func validateNewSSHInput(keyPair *KeyPair, certificateBytes []byte) error {
	var errs []error

	if _, _, err := keyPair.Parse(); err != nil {
		errs = append(errs, fmt.Errorf("invalid key pair: %w", err))
	}

	cert, _, _, _, err := ssh.ParseAuthorizedKey(certificateBytes)
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid certificate: error parsing certificate: %w", err))
	}

	if _, ok := cert.(*ssh.Certificate); !ok {
		errs = append(errs, fmt.Errorf("invalid certificate: error asserting type *ssh.Certificate to parsed certificate: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (k *KeyPair) SignCertificateRequest(rand io.Reader, CertificateRequestBytes []byte, NotBefore, NotAfter time.Time) (certificateBytes []byte, err error) {
	var errs []error

	_, caPrivateKey, err := k.Parse()
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing authority key pair: %w", err))
	}

	certificateRequest, err := ParseCertificateRequest(CertificateRequestBytes)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing certificate request: %w", err))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid input: %w", errors.Join(errs...))
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(certificateRequest.AuthorizedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing authorized public key in certificate request: %w", err)
	}

	certificate := &ssh.Certificate{
		Key:             publicKey,
		Serial:          certificateRequest.SerialNumber.Uint64(),
		CertType:        getCertType(certificateRequest.CertificateType),
		KeyId:           certificateRequest.KeyId,
		ValidPrincipals: certificateRequest.ValidPrincipals,
		ValidAfter:      uint64(NotBefore.Unix()),
		ValidBefore:     uint64(NotAfter.Unix()),
		Permissions:     ssh.Permissions{CriticalOptions: certificateRequest.CriticalOptions, Extensions: certificateRequest.Extensions},
	}

	if err := certificate.SignCert(rand, caPrivateKey); err != nil {
		return nil, fmt.Errorf("error signing certificate: %w", err)
	}

	return ssh.MarshalAuthorizedKey(certificate), nil
}
