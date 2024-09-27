package sshman

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/copartner6412/input/validate"
)

type ClientConfigBlock struct {
	Host            string
	HostName        string
	User            string
	Port            uint16
	IdentityFile    string
	IdentitiesOnly  bool
	CertificateFile string
}

func loadClientConfigFile(clientConfigPath string) (map[string]ClientConfigBlock, error) {
	file, err := os.Open(clientConfigPath)
	if err != nil {
		return nil, fmt.Errorf("error openning client config file: %w", err)
	}

	var block ClientConfigBlock
	blocks := map[string]ClientConfigBlock{}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasSuffix(line, "Host") {
			if block.Host != "" {
				blocks[block.Host] = block
			}
			host := strings.TrimSpace(strings.TrimPrefix(line, "Host"))
			err = validate.LinuxHostname(host, 0, 0)
			if err != nil {
				return nil, fmt.Errorf("invalid")
			}
			block.Host = host
		}

		if strings.HasPrefix(line, "HostName") {
			hostname := strings.TrimSpace(strings.TrimPrefix(line, "HostName"))
			err1 := validate.IP(hostname, "")
			err2 := validate.Domain(hostname, 0, 0)
			if err1 != nil && err2 != nil {
				return nil, fmt.Errorf("invalid hostname for host %s: %w", block.Host, errors.Join(err1, err2))
			}
		}

		if strings.HasPrefix(line, "User") {
			block.User = strings.TrimSpace(strings.TrimPrefix(line, "User"))
		}

		if strings.HasPrefix(line, "Port") {
			portStr := strings.TrimSpace(strings.TrimPrefix(line, "Port"))
			portNum, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("error converting port to integer for host %s: %w", block.Host, err)
			}
			block.Port = uint16(portNum)
		}

		if strings.HasPrefix(line, "IdentityFile") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "IdentityFile"))
			if !filepath.IsAbs(path) {
				return nil, fmt.Errorf("IdentityFile's path %s for host %s is not an absolute path", path, block.Host)
			}
			block.IdentityFile = path
		}

		if strings.HasPrefix(line, "IdentitiesOnly") {
			yerOrNo := strings.TrimSpace(strings.TrimPrefix(line, "IdentitiesOnly"))
			switch yerOrNo {
			case "yes":
				block.IdentitiesOnly = true
			case "", "not":
				block.IdentitiesOnly = false
			default:
				return nil, fmt.Errorf("invalid value for IdentitiesOnly for host %s", yerOrNo)
			}
		}

		if strings.HasPrefix(line, "CertificateFile") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "CertificateFile"))
			if !filepath.IsAbs(path) {
				return nil, fmt.Errorf("CertificateFile's path %s for host %s is not an absolute path", path, block.Host)
			}
		}

		if block.IdentityFile == "" && (block.IdentitiesOnly || block.CertificateFile != "") {
			return nil, fmt.Errorf("IdentityFile not specified but IdentitiesOnly is yes or CertificateFile is specified for host %s", block.Host)
		}
	}

	// Add the last host entry, if any
	if block.Host != "" {
		blocks[block.Host] = block
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return blocks, nil
}

func saveClientConfigFile(blocks map[string]ClientConfigBlock, clientConfigPath string) error {
	var blockSlice []ClientConfigBlock
	var nameSlice []string
	var buf bytes.Buffer

	for name := range blocks {
		nameSlice = append(nameSlice, name)
	}

	sort.Strings(nameSlice)
	for _, name := range nameSlice {
		blockSlice = append(blockSlice, blocks[name])
	}

	for _, block := range blockSlice {
		buf.WriteString(fmt.Sprintf("Host %s\n", block.Host))
		buf.WriteString(fmt.Sprintf("    Hostname %s\n", block.HostName))
		buf.WriteString(fmt.Sprintf("    User %s\n", block.User))
		buf.WriteString(fmt.Sprintf("    Port %d\n", block.Port))
		if block.IdentityFile != "" {
			buf.WriteString(fmt.Sprintf("    IdentityFile %s\n", block.IdentityFile))
			if block.IdentitiesOnly {
				buf.WriteString("    IdentitiesOnly yes\n")
			}
			if block.CertificateFile != "" {
				buf.WriteString(fmt.Sprintf("    CertificateFile %s\n", block.CertificateFile))
			}
		}
		buf.WriteString("\n")
	}

	err := os.WriteFile(clientConfigPath, buf.Bytes(), fs.FileMode(0644))
	if err != nil {
		return fmt.Errorf("error writing data to %s: %w", clientConfigPath, err)
	}

	return nil
}

func DeleteHostFromClientConfig(subject Subject, clientConfigPath string) error {
	if err := validateDeleteHostFromClienConfigInput(subject, clientConfigPath); err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	if clientConfigPath == "" {
		user, err := user.Current()
		if err != nil {
			return fmt.Errorf("error getting current user: %w", err)
		}

		clientConfigPath = filepath.Join(user.HomeDir, "/.ssh/config")
	}

	blocks, err := loadClientConfigFile(clientConfigPath)
	if err != nil {
		return fmt.Errorf("error loading user-specific SSH client configuration file %s: %w", clientConfigPath, err)
	}

	domains := map[string]string{}

	for name, block := range blocks {
		domains[block.HostName] = name
	}

	users := subject.GetSSHUser()

	if len(users) > 1 {
		for _, user := range users {
			_, ok := blocks[subject.GetHostname()]
			if ok {
				host := subject.GetHostname() + "-" + user
				delete(blocks, host)
			}
		}
	} else {
		_, ok := blocks[subject.GetHostname()]
		if ok {
			delete(blocks, subject.GetHostname())
		}
	}

	for _, domain := range subject.GetDomain() {
		_, ok := domains[domain]
		if ok {
			delete(blocks, domains[domain])
		}
	}

	for _, ipv4 := range subject.GetIPv4() {
		_, ok := domains[ipv4]
		if ok {
			delete(blocks, domains[ipv4])
		}
	}

	for _, ipv6 := range subject.GetIPv4() {
		_, ok := domains[ipv6]
		if ok {
			delete(blocks, domains[ipv6])
		}
	}

	if err = saveClientConfigFile(blocks, clientConfigPath); err != nil {
		return fmt.Errorf("error saving user-specific SSH client configuration file: %w", err)
	}

	return nil
}

func validateDeleteHostFromClienConfigInput(subject Subject, clientConfigPath string) error {
	var errs []error

	if err := ValidateSubject(subject); err != nil {
		errs = append(errs, fmt.Errorf("invalid subject: %w", err))
	}

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("error getting current user: %w", err)
	}

	if clientConfigPath != "" {
		if !filepath.IsAbs(clientConfigPath) {
			errs = append(errs, fmt.Errorf("path to user-specific SSH client configuration file %s is not an absolute path", clientConfigPath))
		} else {
			if currentUser.Username != "root" && !strings.HasPrefix(clientConfigPath, currentUser.HomeDir) {
				errs = append(errs, fmt.Errorf("current user %s is not owner of user-specific SSH client configuration file %s", currentUser.Username, clientConfigPath))
			}

			_, err := os.Stat(clientConfigPath)
			if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("file %s not existant", clientConfigPath))
			}
		}

	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func AddHostToClientConfig(subject Subject, clientConfigPath, privateKeyPath, certificatePath string) ([]string, error) {
	if err := validateAddHostToClientConfigInput(subject, clientConfigPath, privateKeyPath, certificatePath); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if clientConfigPath == "" {
		user, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("error getting current user: %w", err)
		}

		clientConfigPath = filepath.Join(user.HomeDir, "/.ssh/config")
	}

	if err := DeleteHostFromClientConfig(subject, clientConfigPath); err != nil {
		return nil, fmt.Errorf("error ensuring there is no host conflicting with subject: %w", err)
	}

	blocks, err := loadClientConfigFile(clientConfigPath)
	if err != nil {
		return nil, fmt.Errorf("error loading user-specific SSH client configuration file %s: %w", clientConfigPath, err)
	}

	var hosts []string

	users := subject.GetSSHUser()

	if len(users) > 1 {
		for _, user := range users {
			host := subject.GetHostname() + "-" + user
			block := ClientConfigBlock{
				Host:         host,
				HostName:     getSSHAddress(subject),
				User:         user,
				Port:         subject.GetSSHPort(),
				IdentityFile: privateKeyPath,
			}
			if privateKeyPath != "" {
				block.IdentitiesOnly = true
				block.CertificateFile = certificatePath
			}

			blocks[host] = block
			hosts = append(hosts, host)
		}
	} else {
		host := subject.GetHostname()
		block := ClientConfigBlock{
			Host:         host,
			HostName:     getSSHAddress(subject),
			User:         subject.GetSSHUser()[0],
			Port:         subject.GetSSHPort(),
			IdentityFile: privateKeyPath,
		}

		if privateKeyPath != "" {
			block.IdentitiesOnly = true
			block.CertificateFile = certificatePath
		}

		blocks[host] = block
		hosts = append(hosts, host)
	}

	if err := saveClientConfigFile(blocks, certificatePath); err != nil {
		return nil, fmt.Errorf("error saving user-specific SSH client configuration file %s: %w", clientConfigPath, err)
	}

	return hosts, nil
}

func validateAddHostToClientConfigInput(subject Subject, clientConfigPath, privateKeyPath, certificatePath string) error {
	var errs []error

	if err := ValidateSubject(subject); err != nil {
		errs = append(errs, fmt.Errorf("invalid subject: %w", err))
	}

	if certificatePath != "" && privateKeyPath == "" {
		errs = append(errs, fmt.Errorf("path to SSH user certificate file can not be specified without path to SSH user private key file"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("error getting current user: %w", err)
	}

	if clientConfigPath != "" {
		if !filepath.IsAbs(clientConfigPath) {
			errs = append(errs, fmt.Errorf("path to user-specific SSH client configuration file %s is not an absolute path", clientConfigPath))
		} else {
			if currentUser.Username != "root" && !strings.HasPrefix(clientConfigPath, currentUser.HomeDir) {
				errs = append(errs, fmt.Errorf("current user %s is not owner of user-specific SSH client configuration file %s", currentUser.Username, clientConfigPath))
			}
		}
	}

	if privateKeyPath != "" {
		if !filepath.IsAbs(privateKeyPath) {
			errs = append(errs, fmt.Errorf("path to SSH private key file is not an absolute path"))
		} else {
			if currentUser.Username != "root" && !strings.HasPrefix(privateKeyPath, currentUser.HomeDir) {
				errs = append(errs, fmt.Errorf("current user %s is not owner of SSH private key file %s", currentUser.Username, privateKeyPath))
			}
		}
	}

	if certificatePath != "" {
		if !filepath.IsAbs(certificatePath) {
			errs = append(errs, fmt.Errorf("path to SSH user certificate file is not an absolute path"))
		} else {
			if currentUser.Username != "root" && !strings.HasPrefix(certificatePath, currentUser.HomeDir) {
				errs = append(errs, fmt.Errorf("current user %s is not owner of SSH user certificate file %s", currentUser.Username, certificatePath))
			}
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	if privateKeyPath != "" {
		_, err := os.Stat(privateKeyPath)
		if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("file %s not existant", privateKeyPath))
		}
	}

	if certificatePath != "" {
		_, err := os.Stat(certificatePath)
		if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("file %s not existant", certificatePath))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func getSSHAddress(subject Subject) string {
	if domains := subject.GetDomain(); len(domains) > 0 {
		return domains[0]
	}

	if ipv4s := subject.GetIPv4(); len(ipv4s) > 0 {
		return ipv4s[0]
	}

	if ipv6s := subject.GetIPv6(); len(ipv6s) > 0 {
		return ipv6s[0]
	}

	return ""
}
