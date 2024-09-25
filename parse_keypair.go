package sshman

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func ParseKeyPair(keyPair KeyPair) (publicKey ssh.PublicKey, privateKey ssh.Signer, err error) {
	var errs []error

	if keyPair.PublicKey == nil {
		errs = append(errs, fmt.Errorf("nil public key"))
	}

	if keyPair.PrivateKey == nil {
		errs = append(errs, fmt.Errorf("nil private key"))
	}

	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}

	publicKey, _, _, _, err = ssh.ParseAuthorizedKey(keyPair.PublicKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing public key: %w", err))
	}

	if keyPair.PrivateKeyPassword == nil {
		privateKey, err = ssh.ParsePrivateKey(keyPair.PrivateKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing private key with password: %w", err))
		}
	} else {
		privateKey, err = ssh.ParsePrivateKeyWithPassphrase(keyPair.PrivateKey, keyPair.PrivateKeyPassword)
		if err != nil {
			errs = append(errs, fmt.Errorf("error parsing private key: %w", err))
		}
	}

	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}

	if !areKeysMatched(publicKey, privateKey) {
		return nil, nil, errors.New("key pair mismatch")
	}

	return publicKey, privateKey, nil
}

func areKeysMatched(publicKey ssh.PublicKey, privateKey ssh.Signer) bool {
	derivedPublicKey := privateKey.PublicKey()

	// Compare the key types
	if publicKey.Type() != derivedPublicKey.Type() {
		return false
	}

	// Compare the marshaled forms of the public keys
	return bytes.Equal(publicKey.Marshal(), derivedPublicKey.Marshal())
}
