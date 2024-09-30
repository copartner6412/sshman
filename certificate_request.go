package sshman

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/ssh"
)

type CertificateRequest struct {
	AuthorizedPublicKey []byte
	SerialNumber        *big.Int
	CertificateType     CertificateType
	KeyId               string
	ValidPrincipals     []string
	ValidAfter          time.Time
	ValidBefore         time.Time
	CriticalOptions     map[string]string
	Extensions          map[string]string
}

func (cr CertificateRequest) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	err := enc.Encode(cr)
	return buf.Bytes(), err
}

func (cr CertificateRequest) SignRequest(rand io.Reader, authority *KeyPair) (certificateBytes []byte, err error) {
	_, caPrivateKey, err := authority.Parse()
	if err != nil {
		return nil, fmt.Errorf("error parsing authority key pair: %w", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(cr.AuthorizedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key in certificate request: %w", err)
	}

	certificate := &ssh.Certificate{
		Key:             publicKey,
		Serial:          cr.SerialNumber.Uint64(),
		CertType:        getCertType(cr.CertificateType),
		KeyId:           cr.KeyId,
		ValidPrincipals: cr.ValidPrincipals,
		ValidAfter:      uint64(cr.ValidAfter.Unix()),
		ValidBefore:     uint64(cr.ValidBefore.Unix()),
		Permissions:     ssh.Permissions{CriticalOptions: cr.CriticalOptions, Extensions: cr.Extensions},
	}

	if err := certificate.SignCert(rand, caPrivateKey); err != nil {
		return nil, fmt.Errorf("error signing certificate: %w", err)
	}

	return ssh.MarshalAuthorizedKey(certificate), nil
}
