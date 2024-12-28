package sshman

import (
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
)

func ParseUserCertificateRequest(certificateRequestBytes []byte) (*UserCertificateRequest, error) {
	cr := new(UserCertificateRequest)
	if err := json.Unmarshal(certificateRequestBytes, cr); err != nil {
		return nil, err
	}

	var errs []error

	if cr.RequesterUsername == "" {
		errs = append(errs, errors.New("empty username"))
	}

	if cr.RequesterPublicKey == nil {
		errs = append(errs, errors.New("nil public key"))
	}

	if cr.Signature == nil {
		errs = append(errs, errors.New("not signed"))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid certificate request: %w", errors.Join(errs...))
	}

	return cr, nil
}

func ParseHostCertificateRequest(certificateRequestBytes []byte) (*HostCertificateRequest, error) {
	cr := new(HostCertificateRequest)
	_, err := asn1.Unmarshal(certificateRequestBytes, cr)
	if err != nil {
		return nil, err
	}

	var errs []error

	if cr.RequesterAddress == "" {
		errs = append(errs, errors.New("empty SSH address"))
	}

	if cr.RequesterPublicKey == nil {
		errs = append(errs, errors.New("nil public key"))
	}

	if cr.Signature == nil {
		errs = append(errs, errors.New("not signed"))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid certificate request: %w", errors.Join(errs...))
	}

	return cr, nil
}
