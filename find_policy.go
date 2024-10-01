package sshman

import "fmt"

var Policies []*CertificatePolicy
var PoliciesByRequester map[string][]*CertificatePolicy
var PoliciesByHost		map[string][]*CertificatePolicy

func FindPoliciesForRequester(certificatePoliciesFilePath, requester string) ([]*CertificatePolicy, error) {
	allPolicies, err := LoadCertificatePolicies(certificatePoliciesFilePath)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate policies: %w", err)
	}

	var policies []*CertificatePolicy

	for _, policy := range allPolicies {
		if policy.Requester == requester {
			policies = append(policies, policy)
		}
	}

	return policies, nil
}

func FindPoliciesForHosts(certificatePoliciesFilePath, host string) ([]*CertificatePolicy, error) {
	allPolicies, err := LoadCertificatePolicies(certificatePoliciesFilePath)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate policies: %w", err)
	}

	var policies []*CertificatePolicy

	for _, policy := range allPolicies {
		if policy.ValidHost == host {
			policies = append(policies, policy)
		}
	}

	return policies, nil
}