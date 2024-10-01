package sshman

import (
	"encoding/json"
)

func UnmarshalCertificateRequest(certificateRequestBytes []byte) (*CertificateRequest, error) {
	var cr *CertificateRequest
	if err := json.Unmarshal(certificateRequestBytes, cr); err != nil {
		return nil, err
	}

	return cr, nil
}