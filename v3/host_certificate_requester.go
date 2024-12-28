package sshman

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type HostCertificateRequester struct {
	SSHAddress              string
	SSHUsers                []string
	SSHPort                 uint16
	AuthenticationPublicKey []byte
}

func (h HostCertificateRequester) Validate() error {
	var errs []error
	if err := validateSSHAddress(h.SSHAddress); err != nil {
		errs = append(errs, fmt.Errorf("invalid SSH address: %w", err))
	}

	if h.SSHUsers == nil {
		errs = append(errs, fmt.Errorf("no users specified"))
	}

	if h.SSHPort == 0 {
		errs = append(errs, fmt.Errorf("SSH port not specified"))
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey(h.AuthenticationPublicKey); err != nil {
		errs = append(errs, fmt.Errorf("error parsing authentication public key: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
