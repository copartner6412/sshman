package sshman

type CertificateType int

const (
	UserCert CertificateType = iota // client
	HostCert                        // server
)

func (ct CertificateType) String() string {
	if ct == UserCert {
		return "user certificate"
	}
	return "host certificate"
}
