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
	ID         string
	IPv4s      []string
	IPv6s      []string
	Domains    []string
	PublicKeys [][]byte
	Port       uint16
	Users      []string
	Hostname   string
	SSHAddress string
}

func AddHost(allHosts []Host, host Host) ([]Host, error) {
	if err := ValidateHost(host); err != nil {
		return nil, fmt.Errorf("invalid host: %w", err)
	}

	found := FindHosts(allHosts, host.ID, host.IPv4s, host.IPv6s, host.Domains, host.PublicKeys)

	for _, foundHost := range found {
		allHosts = DeleteHost(allHosts, foundHost)
	}

	allHosts = append(allHosts, host)

	return allHosts, nil
}

func ValidateHost(host Host) error {
	var errs []error

	for _, ipv4 := range host.IPv4s {
		if err := validate.IP(ipv4, ""); err != nil {
			errs = append(errs, fmt.Errorf("invalid ipv4 \"%s\": %w", ipv4, err))
		}
	}

	for _, ipv6 := range host.IPv6s {
		if err := validate.IP(ipv6, ""); err != nil {
			errs = append(errs, fmt.Errorf("invalid ipv6 \"%s\": %w", ipv6, err))
		}
	}

	for _, domain := range host.Domains {
		if err := validate.Domain(domain, 0, 0); err != nil {
			errs = append(errs, fmt.Errorf("invalid domain \"%s\": %w", domain, err))
		}
	}

	for _, publicKey := range host.PublicKeys {
		if _, _, _, _, err := ssh.ParseAuthorizedKey(publicKey); err != nil {
			errs = append(errs, fmt.Errorf("invalid public key: %w", err))
		}

	}

	err1 := validate.IP(host.SSHAddress, "")
	err2 := validate.Domain(host.SSHAddress, 0, 0)
	if err1 != nil && err2 != nil {
		errs = append(errs, fmt.Errorf("invalid ssh address \"%s\"", host.SSHAddress))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func DeleteHost(allHosts []Host, host Host) []Host {
	found := FindHosts(allHosts, host.ID, host.IPv4s, host.IPv6s, host.Domains, host.PublicKeys)

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

func FindHosts(allHosts []Host, ID string, ipv4s, ipv6s, domains []string, publicKeys [][]byte) (found []Host) {
	hostsByAlias := make(map[string]Host)
	hostsByIPv4 := make(map[string]Host)
	hostsByIPv6 := make(map[string]Host)
	hostsByDomain := make(map[string]Host)
	hostsByPublicKey := make(map[string]Host)
	similar := make(map[string]Host)

	for _, host := range allHosts {
		hostsByAlias[host.ID] = host
		for _, ipv4 := range host.IPv4s {
			hostsByIPv4[ipv4] = host
		}
		for _, ipv6 := range host.IPv6s {
			hostsByIPv6[ipv6] = host
		}
		for _, domain := range host.Domains {
			hostsByDomain[domain] = host
		}
		for _, publicKey := range host.PublicKeys {
			publicKey = bytes.TrimSpace(publicKey)
			hostsByPublicKey[string(publicKey)] = host
		}
	}

	if ID != "" {
		if host, ok := hostsByAlias[ID]; ok {
			similar[host.ID] = host
		}
	}

	for _, ipv4 := range ipv4s {
		if host, ok := hostsByIPv4[ipv4]; ok {
			similar[host.ID] = host
		}
	}

	for _, ipv6 := range ipv6s {
		if host, ok := hostsByIPv4[ipv6]; ok {
			similar[host.ID] = host
		}
	}

	for _, domain := range domains {
		if host, ok := hostsByIPv4[domain]; ok {
			similar[host.ID] = host
		}
	}

	for _, publicKey := range publicKeys {
		publicKey = bytes.TrimSpace(publicKey)
		if host, ok := hostsByPublicKey[string(publicKey)]; ok {
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
