package sshman

import (
	"bytes"
	"encoding/gob"
)

func ParseCertificateRequest(certificateRequestBytes []byte) (CertificateRequest, error) {
	var cr CertificateRequest
	buf := bytes.NewBuffer(certificateRequestBytes)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&cr)
	return cr, err
}
