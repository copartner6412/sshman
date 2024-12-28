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

func (cr UserCertificateRequester) Validate() error {
	var errs []error
	if cr.Username == "" {
		errs = append(errs, errors.New("empty username"))
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey(cr.AuthenticationPublicKey); err != nil {
		errs = append(errs, fmt.Errorf("error parsing authentication public key: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
