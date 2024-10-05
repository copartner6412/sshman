package sshman

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/copartner6412/input/validate"
	"golang.org/x/crypto/ssh"
)

type Host struct {
	ID            string   `json:"id"`
	SSHAddresses  []string `json:"addresses"`
	SSHPublicKeys [][]byte `json:"public_keys"`
	SSHUsers      []string `json:"users"`
	SSHPort       uint16   `json:"port"`
}

func AddHost(allHosts []Host, host Host) ([]Host, error) {
	if err := ValidateHost(host); err != nil {
		return nil, fmt.Errorf("invalid host: %w", err)
	}

	found := FindHosts(allHosts, host.ID, host.SSHAddresses, host.SSHPublicKeys)

	for _, foundHost := range found {
		allHosts = DeleteHost(allHosts, foundHost)
	}

	allHosts = append(allHosts, host)

	return allHosts, nil
}

func ValidateHost(host Host) error {
	var errs []error

	for _, address := range host.SSHAddresses {
		err1 := validate.IP(address, "")
		err2 := validate.Domain(address, 0, 0)
		if err1 != nil && err2 != nil {
			return fmt.Errorf("invalid SSH address \"%s\": %w", address, errors.Join(errs...))
		}
	}

	for _, publicKey := range host.SSHPublicKeys {
		if _, _, _, _, err := ssh.ParseAuthorizedKey(publicKey); err != nil {
			errs = append(errs, fmt.Errorf("invalid public key: %w", err))
		}

	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func DeleteHost(allHosts []Host, host Host) []Host {
	found := FindHosts(allHosts, host.ID, host.SSHAddresses, host.SSHPublicKeys)

	for i, host := range allHosts {
		for _, deleteHost := range found {
			if host.ID == deleteHost.ID {
				allHosts = append(allHosts[:i], allHosts[i+1:]...)
			}
		}
	}

	return allHosts
}

func SaveHosts(authorizedHostsFilePath string, allHosts []Host) error {
	if !filepath.IsAbs(authorizedHostsFilePath) {
		return fmt.Errorf("path to authorized hosts file \"%s\" is not absolute", authorizedHostsFilePath)
	}

	directory := filepath.Dir(authorizedHostsFilePath)

	if err := os.MkdirAll(directory, 0600); err != nil {
		return fmt.Errorf("error creating the directory containing authorized hosts file \"%s\": %w", directory, err)
	}

	if _, err := os.OpenFile(authorizedHostsFilePath, os.O_CREATE, 0600); err != nil {
		return fmt.Errorf("error openning authorized hosts file \"%s\": %w", authorizedHostsFilePath, err)
	}

	var aliases []string
	var allHostsOrdered []Host
	allHostsMap := make(map[string]Host)

	for _, host := range allHosts {
		aliases = append(aliases, host.ID)
		allHostsMap[host.ID] = host
	}

	sort.Strings(aliases)

	for _, alias := range aliases {
		allHostsOrdered = append(allHostsOrdered, allHostsMap[alias])
	}

	data, err := json.MarshalIndent(allHostsOrdered, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling authorized hosts to JSON: %w", err)
	}

	if err := os.WriteFile(authorizedHostsFilePath, data, 0600); err != nil {
		return fmt.Errorf("error writing JSON-encoded data to authorized hosts file \"%s\": %w", authorizedHostsFilePath, err)
	}

	return nil
}

func LoadHosts(authorizedHostsFilePath string) ([]Host, error) {
	if !filepath.IsAbs(authorizedHostsFilePath) {
		return nil, fmt.Errorf("path to authorized hosts file \"%s\" is not absolute", authorizedHostsFilePath)
	}

	info, err := os.Stat(authorizedHostsFilePath)
	if err != nil {
		return nil, fmt.Errorf("error getting authorized hosts file \"%s\" information: %w", authorizedHostsFilePath, err)
	}

	permission := info.Mode().Perm()

	if permission != 0600 {
		return nil, fmt.Errorf("inappropriate permission %d for authorized requesters file \"%s\": chmod to 600", permission, authorizedHostsFilePath)
	}

	data, err := os.ReadFile(authorizedHostsFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading authorized hosts file \"%s\": %w", authorizedHostsFilePath, err)
	}

	var hosts []Host

	if err := json.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("error unmarshaling authorized hosts: %w", err)
	}

	return hosts, nil
}

func FindHosts(allHosts []Host, id string, addresses []string, publicKeys [][]byte) (found []Host) {
	hostsByID := make(map[string]Host)
	hostsBySSHAddress := make(map[string]Host)
	hostsBySSHPublicKey := make(map[string]Host)
	similar := make(map[string]Host)

	for _, host := range allHosts {
		hostsByID[host.ID] = host
		for _, address := range host.SSHAddresses {
			hostsBySSHAddress[address] = host
		}
		for _, publicKey := range host.SSHPublicKeys {
			publicKey = bytes.TrimSpace(publicKey)
			hostsBySSHPublicKey[string(publicKey)] = host
		}
	}

	if host, ok := hostsByID[id]; id != "" && ok {
		similar[host.ID] = host
	}

	for _, address := range addresses {
		if host, ok := hostsBySSHAddress[address]; ok {
			similar[host.ID] = host
		}
	}

	for _, publicKey := range publicKeys {
		publicKey = bytes.TrimSpace(publicKey)
		if host, ok := hostsBySSHPublicKey[string(publicKey)]; ok {
			similar[host.ID] = host
		}
	}

	var aliases []string

	for alias := range similar {
		aliases = append(aliases, alias)
	}

	sort.Strings(aliases)

	for _, alias := range aliases {
		found = append(found, similar[alias])
	}

	return found
}
