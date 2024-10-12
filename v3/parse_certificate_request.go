package sshman

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

func ParseCertificateRequest(certificateRequestBytes []byte) (*UserCertificateRequest, error) {
	cr := new(UserCertificateRequest)
	_, err := asn1.Unmarshal(certificateRequestBytes, cr)
	if err != nil {
		return nil, err
	}

	var errs []error

	if cr.CertificateRequesterUsername == "" {
		errs = append(errs, errors.New("empty username"))
	}

	if cr.CertificateRequesterPublicKey == nil {
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
