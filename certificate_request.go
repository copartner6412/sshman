package sshman

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

type CertificateRequest struct {
	Requester			string
	PublicKey 			[]byte
	RequestedUser		string
	RequestedHost    	string
	CertificateType     CertificateType
	Signature 			[]byte
}

func (cr *CertificateRequest) Marshal() ([]byte, error) {
	return json.Marshal(cr)
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

	cr.Signature = ssh.Marshal(signature)

	return nil
}

func marshalCertificateRequestWithoutSignature(certificateRequest *CertificateRequest) ([]byte, error) {
	crCopy := struct {
		Requester       string
		PublicKey       []byte
		RequestedUser   string
		RequestedHost   string
		CertificateType CertificateType
	}{
		Requester:       certificateRequest.Requester,
		PublicKey:       certificateRequest.PublicKey,
		RequestedUser:   certificateRequest.RequestedUser,
		RequestedHost:   certificateRequest.RequestedHost,
		CertificateType: certificateRequest.CertificateType,
	}

	return json.Marshal(crCopy)
}

func (cr *CertificateRequest) VerifySignature(authenticationPublicKeyBytes []byte) error {
	data, err := marshalCertificateRequestWithoutSignature(cr)
	if err != nil {
		return fmt.Errorf("error marshaling certificate request: %w", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(authenticationPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("error parsing public key: %w", err)
	}

	var signature *ssh.Signature
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