package sshman

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func ParseSSH(sshAsset SSH) (publicKey ssh.PublicKey, privateKey ssh.Signer, certificate *ssh.Certificate, err error) {
	var errs []error
	var ok bool

	if sshAsset.PublicKey == nil {
		errs = append(errs, fmt.Errorf("nil public key"))
	}

	if sshAsset.PrivateKey == nil {
		errs = append(errs, fmt.Errorf("nil private key"))
	}

	if sshAsset.Certificate == nil {
		errs = append(errs, fmt.Errorf("nil pointer to certificate"))
	}

	if len(errs) > 0 {
		return nil, nil, nil, errors.Join(errs...)
	}

	publicKey, _, _, _, err = ssh.ParseAuthorizedKey(sshAsset.PublicKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing public key: %w", err))
	}

	if sshAsset.PrivateKeyPassword == nil {
		privateKey, err = ssh.ParsePrivateKey(sshAsset.PrivateKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing private key with password: %w", err))
		}
	} else {
		privateKey, err = ssh.ParsePrivateKeyWithPassphrase(sshAsset.PrivateKey, sshAsset.PrivateKeyPassword)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing private key: %w", err))
		}
	}

	certificateNotTypeAsserted, _, _, _, err := ssh.ParseAuthorizedKey(sshAsset.Certificate)
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
