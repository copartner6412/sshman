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

func ValidateHostCertificateRequester(host HostCertificateRequester) error {
	var errs []error
	if host.SSHAddress == "" {
		errs = append(errs, errors.New("empty SSH address"))
	} else if err := validateSSHAddress(host.SSHAddress); err != nil {
		errs = append(errs, fmt.Errorf("invalid SSH address: %w", err))
	}

	if host.SSHUsers == nil {
		errs = append(errs, fmt.Errorf("no users specified"))
	}

	if host.SSHPort == 0 {
		errs = append(errs, fmt.Errorf("SSH port not specified"))
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey(host.AuthenticationPublicKey); err != nil {
		errs = append(errs, fmt.Errorf("error parsing authentication public key: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}