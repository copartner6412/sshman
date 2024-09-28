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

func NewCertificateRequest(subject Subject, publicKeyBytes []byte, certificateType CertificateType, validFor time.Duration, criticalOptions, extensions map[string]string) ([]byte, error) {
	if err := validateNewRequestInput(subject, publicKeyBytes, validFor); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serial, err := random.BigInteger(rand.Reader, minSSHCertificateSerialBitSize, maxSSHCertificateSerialBitSize)
	if err != nil {
		return nil, fmt.Errorf("error generating a serial number for SSH certificate: %w", err)
	}

	request := CertificateRequest{
		AuthorizedPublicKey: ssh.MarshalAuthorizedKey(publicKey),
		SerialNumber:        serial,
		CertificateType:     certificateType,
		KeyId:               getKeyID(subject, certificateType),
		ValidPrincipals:     []string{},
		ValidAfter:          notBefore,
		ValidBefore:         notAfter,
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

func validateNewRequestInput(subject Subject, publicKeyBytes []byte, validFor time.Duration) error {
	var errs []error

	if err := ValidateSubject(subject); err != nil {
		errs = append(errs, fmt.Errorf("invalid subject: %w", err))
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
