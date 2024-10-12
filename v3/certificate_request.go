package sshman

import (
	"encoding/asn1"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

type UserCertificateRequest struct {
	CertificateRequesterUsername  string `asn1:"utf8"`
	CertificateRequesterPublicKey []byte `asn1:"octet"`
	RequestedUser                 string `asn1:"utf8,omitempty"`
	RequestedHost                 string `asn1:"utf8,omitempty"`
	Signature                     []byte `asn1:"octet"`
}

type HostCertificateRequest struct {
	CertificateRequesterSSHAddress string `asn1:"utf8"`
	CertificateRequesterPublicKey  []byte `asn1:"octet"`
	Signature                      []byte `asn1:"octet"`
}

func (cr *UserCertificateRequest) Marshal() ([]byte, error) {
	return asn1.Marshal(*cr)
}

func (cr *HostCertificateRequest) Marshal() ([]byte, error) {
	return asn1.Marshal(*cr)
}

func (cr *UserCertificateRequest) Sign(randomness io.Reader, authenticationKeyPair *KeyPair) error {
	_, privateKey, err := authenticationKeyPair.Parse()
	if err != nil {
		return fmt.Errorf("error parsing authentication key pair: %w", err)
	}

	data, err := marshalCertificateRequestWithoutSignature(cr)
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

	data, err := marshalCertificateRequestWithoutSignature(cr)
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

func marshalCertificateRequestWithoutSignature(certificateRequest any) ([]byte, error) {
	switch request := certificateRequest.(type) {
	case *UserCertificateRequest:
		crCopy := struct {
			CertificateRequesterUsername  string `asn1:"utf8"`
			CertificateRequesterPublicKey []byte `asn1:"octet"`
			RequestedUser                 string `asn1:"utf8,omitempty"`
			RequestedHost                 string `asn1:"utf8,omitempty"`
		}{
			CertificateRequesterUsername:  request.CertificateRequesterUsername,
			CertificateRequesterPublicKey: request.CertificateRequesterPublicKey,
			RequestedUser:                 request.RequestedUser,
			RequestedHost:                 request.RequestedHost,
		}
		return asn1.Marshal(crCopy)
	case *HostCertificateRequest:
		crCopy := struct {
			CertificateRequesterSSHAddress string `asn1:"utf8"`
			CertificateRequesterPublicKey  []byte `asn1:"octet"`
		}{
			CertificateRequesterSSHAddress: request.CertificateRequesterSSHAddress,
			CertificateRequesterPublicKey:  request.CertificateRequesterPublicKey,
		}
		return asn1.Marshal(crCopy)
	default:
		return nil, fmt.Errorf("unsupported type %T", certificateRequest)
	}
}

func (cr *UserCertificateRequest) Authenticate(authenticationPublicKeyBytes []byte) error {
	data, err := marshalCertificateRequestWithoutSignature(cr)
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
	data, err := marshalCertificateRequestWithoutSignature(cr)
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
