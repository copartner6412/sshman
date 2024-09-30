package sshman

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/copartner6412/input/random"
	"golang.org/x/crypto/ssh"
)

const (
	serialNumberBitSize uint          = 64
	minDurationAllowed  time.Duration = 1 * time.Second
	maxDurationAllowed  time.Duration = 20 * 365 * 24 * time.Hour
)

func CreateCertificateRequest(subject Subject, publicKeyBytes []byte, certificateType CertificateType, criticalOptions, extensions map[string]string) ([]byte, error) {
	if err := validateNewRequestInput(subject, publicKeyBytes); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	serial, err := random.BigInteger(rand.Reader, serialNumberBitSize, serialNumberBitSize)
	if err != nil {
		return nil, fmt.Errorf("error generating a serial number for SSH certificate: %w", err)
	}

	request := CertificateRequest{
		AuthorizedPublicKey: ssh.MarshalAuthorizedKey(publicKey),
		SerialNumber:        serial,
		CertificateType:     certificateType,
		KeyId:               getKeyID(subject, certificateType),
		ValidPrincipals:     []string{},
		CriticalOptions:     criticalOptions,
		Extensions:          extensions,
	}

	if certificateType == UserCert {
		request.ValidPrincipals = getPrincipals(subject, certificateType)
	}

	requestBytes, err := request.Marshal()
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}

	return requestBytes, nil
}

func validateNewRequestInput(subject Subject, publicKeyBytes []byte) error {
	var errs []error

	if err := ValidateSubject(subject); err != nil {
		errs = append(errs, fmt.Errorf("invalid subject: %w", err))
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyBytes); err != nil {
		errs = append(errs, fmt.Errorf("invalid public key: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
