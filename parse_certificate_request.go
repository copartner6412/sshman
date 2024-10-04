package sshman

import (
	"encoding/asn1"
)

func ParseCertificateRequest(certificateRequestBytes []byte) (*CertificateRequest, error) {
	cr := new(CertificateRequest)
	_, err := asn1.Unmarshal(certificateRequestBytes, cr)
	if err != nil {
		return nil, err
	}

	return cr, nil
}
