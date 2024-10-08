package sshman

type CertificateRequesterType string

const (
	UserRequester CertificateRequesterType = "user" // client
	HostRequester CertificateRequesterType = "host"                                // server
)
