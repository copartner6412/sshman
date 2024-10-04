package sshman

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type CertificatePolicy struct {
	ID              string
	RequesterID     string
	CertificateType CertificateType
	ValidUser       string `json:"ValidUser,omitempty"`
	ValidHostAlias  string
	ValidAfter      time.Time
	ValidBefore     time.Time
	CriticalOptions map[string]string
	Extensions      map[string]string
}

func AddCertificatePolicy(allPolicies []CertificatePolicy, policy CertificatePolicy) ([]CertificatePolicy, error) {
	if err := ValidateCertificatePolicy(policy); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	allPolicies = DeleteCertificatePolicy(allPolicies, policy)

	allPolicies = append(allPolicies, policy)

	return allPolicies, nil
}

func ValidateCertificatePolicy(policy CertificatePolicy) error {
	var errs []error

	if policy.RequesterID == "" {
		errs = append(errs, errors.New("empty requester"))
	}

	if policy.CertificateType == UserCert {
		if policy.ValidUser == "" {
			errs = append(errs, errors.New("empty user"))
		}

		if policy.ValidHostAlias == "" {
			errs = append(errs, errors.New("empty host alias"))
		}

		if _, ok := policy.CriticalOptions["source-address"]; !ok {
			errs = append(errs, errors.New("critical option source address not specified"))
		}
	}

	if !policy.ValidBefore.After(policy.ValidAfter) {
		errs = append(errs, errors.New("start time after end time"))
	}

	if policy.ValidBefore.Before(time.Now()) {
		errs = append(errs, errors.New("policy already expired"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func DeleteCertificatePolicy(allPolicies []CertificatePolicy, policy CertificatePolicy) []CertificatePolicy {
	foundPolicies := FindCertificatePolicies(allPolicies, policy.CertificateType, policy.RequesterID, policy.ValidUser, policy.ValidHostAlias)

	for i, policy := range allPolicies {
		for _, foundPolicy := range foundPolicies {
			if policy.RequesterID == foundPolicy.RequesterID && policy.ValidUser == foundPolicy.ValidUser && policy.ValidHostAlias == foundPolicy.ValidHostAlias {
				allPolicies = append(allPolicies[:i], allPolicies[i+1:]...)
			}
		}
	}

	return allPolicies
}

func SaveCertificatePolicies(certificatePoliciesFilePath string, allPolicies []CertificatePolicy) error {
	if !filepath.IsAbs(certificatePoliciesFilePath) {
		return fmt.Errorf("path to certificate policies file \"%s\" is not absolute", certificatePoliciesFilePath)
	}

	directory := filepath.Dir(certificatePoliciesFilePath)

	if err := os.MkdirAll(directory, 0600); err != nil {
		return fmt.Errorf("error creating the directory containing certificate policies file: %w", err)
	}

	if _, err := os.OpenFile(certificatePoliciesFilePath, os.O_CREATE, 0600); err != nil {
		return fmt.Errorf("error openning the certificate policies file \"%s\": %w", certificatePoliciesFilePath, err)
	}

	data, err := json.MarshalIndent(allPolicies, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling certificate policies to JSON: %w", err)
	}

	if err := os.WriteFile(certificatePoliciesFilePath, data, 0600); err != nil {
		return fmt.Errorf("error writing JSON-encoded data to certificate policies file \"%s\": %w", certificatePoliciesFilePath, err)
	}

	return nil
}

func LoadCertificatePolicies(certificatePoliciesFilePath string) ([]CertificatePolicy, error) {
	if !filepath.IsAbs(certificatePoliciesFilePath) {
		return nil, fmt.Errorf("path to certificate policies file \"%s\" is not absolute", certificatePoliciesFilePath)
	}

	info, err := os.Stat(certificatePoliciesFilePath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("file \"%s\" not existant", certificatePoliciesFilePath)
	}

	permission := info.Mode().Perm()

	if permission != 0600 {
		return nil, fmt.Errorf("inappropriate permission %d: chmod to 600", permission)
	}

	data, err := os.ReadFile(certificatePoliciesFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file \"%s\": %w", certificatePoliciesFilePath, err)
	}

	var policies []CertificatePolicy

	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("error unmarshaling certificate policies: %w", err)
	}

	return policies, nil
}

func FindCertificatePolicies(allPolicies []CertificatePolicy, certificateType CertificateType, requester, user, host string) []CertificatePolicy {
	var policies []CertificatePolicy

	if requester != "" && host != "" {
		for _, policy := range allPolicies {
			if policy.RequesterID == requester && policy.ValidHostAlias == host {
				policies = append(policies, policy)
			}
		}
	} else if requester != "" && host == "" {
		for _, policy := range allPolicies {
			if policy.RequesterID == requester {
				policies = append(policies, policy)
			}
		}
	} else if requester == "" && host != "" {
		for _, policy := range allPolicies {
			if policy.ValidHostAlias == host {
				policies = append(policies, policy)
			}
		}
	} else {
		policies = allPolicies
	}

	var userPolicies []CertificatePolicy

	if certificateType == UserCert {
		if user != "" {
			for _, policy := range policies {
				if policy.ValidUser == user {
					userPolicies = append(userPolicies, policy)
				}
			}
		}
		return userPolicies
	}

	return policies
}
