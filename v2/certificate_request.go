package sshman

import (
	"encoding/asn1"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

type CertificateRequest struct {
	RequesterID        string          `asn1:"utf8"`
	RequesterPublicKey []byte          `asn1:"octet"`
	RequestedUser      string          `asn1:"utf8,omitempty"`
	RequestedHost      string          `asn1:"utf8"`
	CertificateType    CertificateType `asn1:"tag:1"`
	Signature          []byte          `asn1:"octet"`
}

func (cr CertificateRequest) Marshal() ([]byte, error) {
	return asn1.Marshal(cr)
}

func (cr *CertificateRequest) Sign(randomness io.Reader, authenticationKeyPair *KeyPair) error {
	_, privateKey, err := authenticationKeyPair.Parse()
	if err != nil {
		return fmt.Errorf("error parsing authentication key pair: %w", err)
	}

	data, err := marshalCertificateRequestWithoutSignature(cr)
	if err != nil {
		return fmt.Errorf("error marshaling certificate request: %w", err)
	}

	signature, err := privateKey.Sign(randomness, data)
	if err != nil {
		return fmt.Errorf("error signing the certificate request: %w", err)
	}

	cr.Signature = ssh.Marshal(*signature)

	return nil
}

func marshalCertificateRequestWithoutSignature(certificateRequest *CertificateRequest) ([]byte, error) {
	crCopy := struct {
		RequesterID        string          `asn1:"utf8"`
		RequesterPublicKey []byte          `asn1:"octet"`
		RequestedUser      string          `asn1:"utf8,omitempty"`
		RequestedHost      string          `asn1:"utf8,omitempty"`
		CertificateType    CertificateType `asn1:"tag:1"`
	}{
		RequesterID:        certificateRequest.RequesterID,
		RequesterPublicKey: certificateRequest.RequesterPublicKey,
		RequestedUser:      certificateRequest.RequestedUser,
		RequestedHost:      certificateRequest.RequestedHost,
		CertificateType:    certificateRequest.CertificateType,
	}

	return asn1.Marshal(crCopy)
}

func (cr *CertificateRequest) Authenticate(authenticationPublicKeyBytes []byte) error {
	data, err := marshalCertificateRequestWithoutSignature(cr)
	if err != nil {
		return fmt.Errorf("error marshaling certificate request: %w", err)
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
