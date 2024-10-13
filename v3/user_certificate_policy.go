package sshman

import (
	"errors"
	"fmt"
	"time"
)

type UserCertificatePolicy struct {
	CertificateRequesterUsername string
	ValidHost                    string
	ValidUser                    string
	ValidAfter                   time.Time
	ValidBefore                  time.Time
	CriticalOptions              map[string]string
	Extensions                   map[string]string
}

func ValidateUserCertificatePolicy(policy UserCertificatePolicy) error {
	var errs []error

	if policy.CertificateRequesterUsername == "" {
		errs = append(errs, errors.New("empty certificate requester username"))
	}

	if policy.ValidHost == "" {
		errs = append(errs, errors.New("empty host SSH address"))
	} else if err := validateSSHAddress(policy.ValidHost); err != nil {
		errs = append(errs, fmt.Errorf("invalid host SSH address: %w", err))
	}

	if policy.ValidUser == "" {
		errs = append(errs, errors.New("empty user"))
	}

	if policy.ValidAfter.IsZero() {
		errs = append(errs, errors.New("zero starting time"))
	}

	if policy.ValidBefore.IsZero() {
		errs = append(errs, errors.New("zero ending time"))
	}

	if policy.CriticalOptions["source-address"] != policy.ValidHost {
		errs = append(errs, errors.New("source address mismatch"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}