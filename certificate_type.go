package sshman

type CertificateType int

const (
	UserCert CertificateType = iota // client
	HostCert                        // server
)
