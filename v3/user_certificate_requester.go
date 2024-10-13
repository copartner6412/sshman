package sshman

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type UserCertificateRequester struct {
	Username                string
	Name                    string
	AuthenticationPublicKey []byte
}

func ValidateUserCertificateRequester(certificateRequester UserCertificateRequester) error {
	var errs []error
	if certificateRequester.Username == "" {
		errs = append(errs, errors.New("empty username"))
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey(certificateRequester.AuthenticationPublicKey); err != nil {
		errs = append(errs, fmt.Errorf("error parsing authentication public key: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}