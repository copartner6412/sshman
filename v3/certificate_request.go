package sshman

import (
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

type UserCertificateRequest struct {
	RequesterUsername  string `json:"username"`
	RequesterPublicKey []byte `json:"public_key"`
	RequestedUser      string `json:"user,omitempty"`
	RequestedHost      string `json:"host,omitempty"`
	Signature          []byte `json:"-"`
}

type HostCertificateRequest struct {
	RequesterAddress   string `json:"address"`
	RequesterPublicKey []byte `json:"public_key"`
	Signature          []byte `json:"-"`
}

func (cr *UserCertificateRequest) Sign(randomness io.Reader, authenticationKeyPair *KeyPair) error {
	_, privateKey, err := authenticationKeyPair.Parse()
	if err != nil {
		return fmt.Errorf("error parsing authentication key pair: %w", err)
	}

	data, err := json.Marshal(*cr)
	if err != nil {
		return fmt.Errorf("error marshaling host certificate request: %w", err)
	}

	signature, err := privateKey.Sign(randomness, data)
	if err != nil {
		return fmt.Errorf("error signing host certificate request: %w", err)
	}

	cr.Signature = ssh.Marshal(*signature)

	return nil
}

func (cr *HostCertificateRequest) Sign(randomness io.Reader, authenticationKeyPair *KeyPair) error {
	_, privateKey, err := authenticationKeyPair.Parse()
	if err != nil {
		return fmt.Errorf("error parsing authentication key pair: %w", err)
	}

	data, err := json.Marshal(*cr)
	if err != nil {
		return fmt.Errorf("error marshaling user certificate request: %w", err)
	}

	signature, err := privateKey.Sign(randomness, data)
	if err != nil {
		return fmt.Errorf("error signing user certificate request: %w", err)
	}

	cr.Signature = ssh.Marshal(*signature)

	return nil
}

func (cr *UserCertificateRequest) Authenticate(authenticationPublicKeyBytes []byte) error {
	data, err := json.Marshal(*cr)
	if err != nil {
		return fmt.Errorf("error marshaling host certificate request: %w", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(authenticationPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("error parsing public key: %w", err)
	}

	signature := new(ssh.Signature)
	err = ssh.Unmarshal(cr.Signature, signature)
	if err != nil {
		return fmt.Errorf("error unmarshaling signature: %w", err)
	}

	err = publicKey.Verify(data, signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func (cr *HostCertificateRequest) Authenticate(authenticationPublicKeyBytes []byte) error {
	data, err := json.Marshal(*cr)
	if err != nil {
		return fmt.Errorf("error marshaling user certificate request: %w", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(authenticationPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("error parsing public key: %w", err)
	}

	signature := new(ssh.Signature)
	err = ssh.Unmarshal(cr.Signature, signature)
	if err != nil {
		return fmt.Errorf("error unmarshaling signature: %w", err)
	}

	err = publicKey.Verify(data, signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
