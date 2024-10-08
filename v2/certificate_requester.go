package sshman

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/crypto/ssh"
)

type CertificateRequester struct {
	ID                      string `json:"id"`
	Name                    string `json:"name,omitempty"`
	AuthenticationPublicKey []byte `json:"public_key"`
	Type                    string `json:"type"`
}

func SaveCertificateRequesters(authorizedRequestersFilePath string, allRequesters []CertificateRequester) error {
	if !filepath.IsAbs(authorizedRequestersFilePath) {
		return fmt.Errorf("path to authorized requesters file \"%s\" is not an absolute path", authorizedRequestersFilePath)
	}

	directory := filepath.Dir(authorizedRequestersFilePath)

	if err := os.MkdirAll(directory, 0600); err != nil {
		return fmt.Errorf("error creating the directory containing authorized requester file \"%s\": %w", directory, err)
	}

	if _, err := os.OpenFile(authorizedRequestersFilePath, os.O_CREATE, 0600); err != nil {
		return fmt.Errorf("error openning authorized requesters file \"%s\": %w", authorizedRequestersFilePath, err)
	}

	var ids []string
	var allRequestersOrdered []CertificateRequester
	allRequestersMap := make(map[string]CertificateRequester)

	for _, requester := range allRequesters {
		ids = append(ids, requester.ID)
		allRequestersMap[requester.ID] = requester
	}

	sort.Strings(ids)

	for _, id := range ids {
		allRequestersOrdered = append(allRequestersOrdered, allRequestersMap[id])
	}

	data, err := json.MarshalIndent(allRequestersOrdered, "", " ")
	if err != nil {
		return fmt.Errorf("error marshaling authorized requester to JSON: %w", err)
	}

	if err := os.WriteFile(authorizedRequestersFilePath, data, 0600); err != nil {
		return fmt.Errorf("error writing JSON-encoded data to authorized requesters file \"%s\": %w", authorizedRequestersFilePath, err)
	}

	return nil
}

func LoadCertificateRequesters(authorizedRequestersFilePath string) ([]CertificateRequester, error) {
	if !filepath.IsAbs(authorizedRequestersFilePath) {
		return nil, fmt.Errorf("path to authorized requesters file \"%s\" is not absolute", authorizedRequestersFilePath)
	}

	info, err := os.Stat(authorizedRequestersFilePath)
	if err != nil {
		return nil, fmt.Errorf("error getting authorized requesters file \"%s\" information: %w", authorizedRequestersFilePath, err)
	}

	permission := info.Mode().Perm()
	if permission != 0600 {
		return nil, fmt.Errorf("inappropriate permission %d for authorized requesters file \"%s\": chmod to 600", permission, authorizedRequestersFilePath)
	}

	data, err := os.ReadFile(authorizedRequestersFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading authorized requesters file \"%s\": %w", authorizedRequestersFilePath, err)
	}

	var requesters []CertificateRequester

	if err := json.Unmarshal(data, &requesters); err != nil {
		return nil, fmt.Errorf("error unmarshaling authorized requesters: %w", err)
	}

	return requesters, nil
}

func AddCertificateRequester(allRequesters []CertificateRequester, requester CertificateRequester) ([]CertificateRequester, error) {
	if err := ValidateCertificateRequester(requester); err != nil {
		return nil, fmt.Errorf("invalid requester: %w", err)
	}

	found := FindCertificateRequesters(allRequesters, requester.ID, "", nil)
	for _, foundRequester := range found {
		allRequesters = DeleteCertificateRequester(allRequesters, foundRequester)
	}

	return append(allRequesters, requester), nil
}

func ValidateCertificateRequester(requester CertificateRequester) error {
	var errs []error
	if requester.ID == "" {
		errs = append(errs, errors.New("empty username"))
	}

	if requester.Type != UserCert.String() && requester.Type != HostCert.String() {
		errs = append(errs, fmt.Errorf("invalid type \"%s\"", requester.Type))
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey(requester.AuthenticationPublicKey); err != nil {
		errs = append(errs, fmt.Errorf("invalid public key: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func DeleteCertificateRequester(allRequesters []CertificateRequester, deleteRequester CertificateRequester) []CertificateRequester {
	for i, requester := range allRequesters {
		if requester.ID == deleteRequester.ID && bytes.Equal(requester.AuthenticationPublicKey, deleteRequester.AuthenticationPublicKey) {
			allRequesters = append(allRequesters[:i], allRequesters[i+1:]...)
		}
	}

	return allRequesters
}

func FindCertificateRequesters(allRequesters []CertificateRequester, id, name string, publicKey []byte) (found []CertificateRequester) {
	requestersByID := make(map[string]CertificateRequester)
	requestersByName := make(map[string]CertificateRequester)
	requestersByPublicKey := make(map[string]CertificateRequester)
	similar := make(map[string]CertificateRequester)

	publicKey = bytes.TrimSpace(publicKey)

	for _, requester := range allRequesters {
		requestersByID[requester.ID] = requester
		requestersByName[requester.Name] = requester
		publicKey = bytes.TrimSpace(publicKey)
		requestersByPublicKey[string(publicKey)] = requester
	}

	if requester, ok := requestersByID[id]; id != "" && ok {
		similar[requester.ID] = requester
	}

	if requester, ok := requestersByName[name]; name != "" && ok {
		similar[requester.ID] = requester
	}

	if requester, ok := requestersByPublicKey[string(publicKey)]; len(publicKey) != 0 && ok {
		similar[requester.ID] = requester
	}

	var ids []string

	for id := range similar {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	for _, id := range ids {
		found = append(found, similar[id])
	}

	return found
}
