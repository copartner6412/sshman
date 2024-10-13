package sshman

import (
	"errors"
	"fmt"
	"time"

	"github.com/copartner6412/input/validate"
)

type HostCertificatePolicy struct {
	CertificateRequesterSSHAddress string
	ValidAfter                     time.Time
	ValidBefore                    time.Time
	CriticalOptions                map[string]string
	Extensions                     map[string]string
}

func ValidateHostCertificatePolicy(policy HostCertificatePolicy) error {
	var errs []error

	if policy.CertificateRequesterSSHAddress == "" {
		errs = append(errs, errors.New("empty SSH address"))
	} else if err := validateSSHAddress(policy.CertificateRequesterSSHAddress); err != nil {
		errs = append(errs, fmt.Errorf("invalid SSH address: %w", err))
	}

	if policy.ValidAfter.IsZero() {
		errs = append(errs, errors.New("zero starting time"))
	}

	if policy.ValidBefore.IsZero() {
		errs = append(errs, errors.New("zero ending time"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func validateSSHAddress(sshAddress string) error {
	if sshAddress == "" {
		return fmt.Errorf("empty SSH address")
	}

	err1 := validate.IP(sshAddress, "")
	err2 := validate.Domain(sshAddress, 0, 0)
	if err1 != nil && err2 != nil {
		return errors.Join(err1, err2)
	}

	return nil
}