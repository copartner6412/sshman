package sshman

func CreateCertificate(request *CertificateRequest, policy *CertificatePolicy, ca *KeyPair) ([]byte, error) {
	allPolicies := FindPoliciesFor(request.Requester)

	var policies []*CertificatePolicy

	for _, policy := range allPolicies {
		if request.RequestedUser != "" && 
	}
}