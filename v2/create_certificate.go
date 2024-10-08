package sshman

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/copartner6412/input/random"
	"golang.org/x/crypto/ssh"
)

func CreateCertificate(ca *KeyPair, requestBytes []byte, authorizedRequestersFilePath, authorizedHostsFilePath, certificatePoliciesFilePath string) ([][]byte, error) {
	_, caPrivateKey, err := ca.Parse()
	if err != nil {
		return nil, fmt.Errorf("error parsing CA key pair: %w", err)
	}

	allRequesters, err := LoadCertificateRequesters(authorizedRequestersFilePath)
	if err != nil {
		return nil, fmt.Errorf("error loading authorized certificate requesters file \"%s\": %w", authorizedRequestersFilePath, err)
	}

	allPolicies, err := LoadCertificatePolicies(certificatePoliciesFilePath)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate policies file \"%s\": %w", certificatePoliciesFilePath, err)
	}

	request, err := ParseCertificateRequest(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate request: %w", err)
	}

	requesters := FindCertificateRequesters(allRequesters, request.RequesterID, "", nil)

	if len(requesters) == 0 {
		return nil, fmt.Errorf("no authorized requester with ID \"%s\"", request.RequesterID)
	}

	if err := request.Authenticate(requesters[0].AuthenticationPublicKey); err != nil {
		return nil, fmt.Errorf("public key authentication for requester \"%s\" with ID \"%s\" failed: %w", requesters[0].Name, requesters[0].ID, err)
	}

	policies := FindCertificatePolicies(allPolicies, request.CertificateType.String(), request.RequesterID, request.RequestedUser, request.RequestedHost)
	if len(policies) == 0 {
		return nil, fmt.Errorf("no policy for request with requster ID \"%s\", requested user \"%s\", and requested host \"%s\"", request.RequesterID, request.RequestedUser, request.RequestedHost)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(request.RequesterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing request public key: %w", err)
	}

	serial, err := random.BigInteger(rand.Reader, 65, 128)
	if err != nil {
		return nil, fmt.Errorf("error generating a random serial number: %w", err)
	}

	allHosts, err := LoadHosts(authorizedHostsFilePath)
	if err != nil {
		return nil, fmt.Errorf("error loading hosts: %w", err)
	}

	hosts := FindHosts(allHosts, request.RequestedHost, []string{request.RequestedHost}, nil)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no host for specified identifier \"%s\"", request.RequestedHost)
	} else if len(hosts) > 1 {
		return nil, fmt.Errorf("there is more than one host for specified identifier \"%s\"", request.RequestedHost)
	}

	var certificates [][]byte

	for _, policy := range policies {
		certificate := &ssh.Certificate{
			Key:         publicKey,
			Serial:      serial.Uint64(),
			ValidAfter:  uint64(policy.ValidAfter.Unix()),
			ValidBefore: uint64(policy.ValidBefore.Unix()),
			Permissions: ssh.Permissions{
				CriticalOptions: policy.CriticalOptions,
				Extensions:      policy.Extensions,
			},
		}

		if request.CertificateType == UserCert {
			certificate.CertType = ssh.UserCert
			certificate.KeyId = strings.Join([]string{"user", request.RequesterID, request.RequestedUser + "@" + request.RequestedHost, publicKey.Type()}, "_")
			certificate.ValidPrincipals = []string{policy.ValidUser}
			if policy.CriticalOptions["source-address"] != hosts[0].SSHAddresses[0] {
				return nil, fmt.Errorf("invalid source address \"%s\" for user certificate policy \"%s\"", hosts[0].SSHAddresses[0], policy.ID)
			}
		} else {
			certificate.CertType = ssh.HostCert
			certificate.KeyId = strings.Join([]string{"host", request.RequesterID, publicKey.Type()}, "_")
		}

		if err := certificate.SignCert(rand.Reader, caPrivateKey); err != nil {
			return nil, fmt.Errorf("error siging certificate: %w", err)
		}

		certificateBytes := ssh.MarshalAuthorizedKey(certificate)

		certificates = append(certificates, certificateBytes)
	}

	return certificates, nil
}
