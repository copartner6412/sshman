package sshman

import "time"

type CertificatePolicy struct {
	Requester			string
	PublicKey			string
	ValidUser	    	string
	ValidHost			string
	ValidAfter			time.Time
	ValidBefore			time.Time
	CriticalOptions		map[string]string
	Extensions			map[string]string
}

func SaveCertificatePolicies(certificatePoliciesFilePath string, policies []*CertificatePolicy) error {

}

func LoadCertificatePolicies(certificatePoliciesFilePath string) ([]*CertificatePolicy, error) {

}
