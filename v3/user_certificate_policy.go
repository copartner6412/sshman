package sshman

import (
	"errors"
	"fmt"
	"time"
)

type UserCertificatePolicy struct {
	RequesterUsername string
	ValidHost         string
	ValidUser         string
	ValidAfter        time.Time
	ValidBefore       time.Time
	CriticalOptions   map[string]string
	Extensions        map[string]string
}

func (p UserCertificatePolicy) Validate() error {
	var errs []error

	if p.RequesterUsername == "" {
		errs = append(errs, errors.New("empty certificate requester username"))
	}

	if p.ValidHost == "" {
		errs = append(errs, errors.New("empty host SSH address"))
	} else if err := validateSSHAddress(p.ValidHost); err != nil {
		errs = append(errs, fmt.Errorf("invalid host SSH address: %w", err))
	}

	if p.ValidUser == "" {
		errs = append(errs, errors.New("empty user"))
	}

	if p.ValidAfter.IsZero() {
		errs = append(errs, errors.New("zero starting time"))
	}

	if p.ValidBefore.IsZero() {
		errs = append(errs, errors.New("zero ending time"))
	}

	if p.CriticalOptions["source-address"] != p.ValidHost {
		errs = append(errs, errors.New("source address mismatch"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
