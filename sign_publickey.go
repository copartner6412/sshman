package sshman

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/copartner6412/input/random"
	"github.com/copartner6412/input/validate"
	"golang.org/x/crypto/ssh"
)

func SignPublicKey(subject Subject, ca KeyPair, publicKeyBytes []byte, certificateType CertificateType, validFor time.Duration) ([]byte, error) {
	if err := validateSignInput(subject, ca, publicKeyBytes, validFor); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	_, caPrivateKey, err := ParseKeyPair(ca)
	if err != nil {
		return nil, fmt.Errorf("error parsing CA: %w", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serial, err := random.BigInteger(minSSHCertificateSerialBitSize, maxSSHCertificateSerialBitSize)
	if err != nil {
		return nil, fmt.Errorf("error generating a serial number for SSH certificate: %w", err)
	}

	certificate := &ssh.Certificate{
		Key:         publicKey,
		Serial:      serial.Uint64(),
		CertType:    getCertType(certificateType),
		KeyId:       getKeyID(subject, certificateType),
		ValidAfter:  uint64(notBefore.Unix()),
		ValidBefore: uint64(notAfter.Unix()),
	}

	if certificateType == UserCert {
		certificate.ValidPrincipals = getPrincipals(subject, certificateType)
	}

	if err := certificate.SignCert(rand.Reader, caPrivateKey); err != nil {
		return nil, fmt.Errorf("error signing certificate: %w", err)
	}

	return ssh.MarshalAuthorizedKey(certificate), nil
}

func validateSignInput(subject Subject, ca KeyPair, publicKeyBytes []byte, validFor time.Duration) error {
	var errs []error
	if err := ValidateSubject(subject); err != nil {
		errs = append(errs, fmt.Errorf("invalid subject: %w", err))
	}

	if _, _, err := ParseKeyPair(ca); err != nil {
		errs = append(errs, fmt.Errorf("invalid CA: %w", err))
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyBytes); err != nil {
		errs = append(errs, fmt.Errorf("invalid public key: %w", err))
	}

	if err := validate.Duration(validFor, minDurationAllowed, maxDurationAllowed); err != nil {
		errs = append(errs, fmt.Errorf("invalid duration: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
