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

type clientConfigBlock struct {
	host            string
	hostName        string
	user            string
	port            uint16
	identityFile    string
	identitiesOnly  bool
	certificateFile string
}

func loadClientConfigFile(clientConfigPath string) (map[string]clientConfigBlock, error) {
	file, err := os.Open(clientConfigPath)
	if err != nil {
		return nil, fmt.Errorf("error openning client config file: %w", err)
	}

	var block clientConfigBlock
	blocks := map[string]clientConfigBlock{}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasSuffix(line, "Host") {
			if block.host != "" {
				blocks[block.host] = block
			}
			host := strings.TrimSpace(strings.TrimPrefix(line, "Host"))
			err = validate.LinuxHostname(host, 0, 0)
			if err != nil {
				return nil, fmt.Errorf("invalid")
			}
			block.host = host
		}

		if strings.HasPrefix(line, "HostName") {
			hostname := strings.TrimSpace(strings.TrimPrefix(line, "HostName"))
			err1 := validate.IP(hostname, "")
			err2 := validate.Domain(hostname, 0, 0)
			if err1 != nil && err2 != nil {
				return nil, fmt.Errorf("invalid hostname for host %s: %w", block.host, errors.Join(err1, err2))
			}
		}

		if strings.HasPrefix(line, "User") {
			block.user = strings.TrimSpace(strings.TrimPrefix(line, "User"))
		}

		if strings.HasPrefix(line, "Port") {
			portStr := strings.TrimSpace(strings.TrimPrefix(line, "Port"))
			portNum, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("error converting port to integer for host %s: %w", block.host, err)
			}
			block.port = uint16(portNum)
		}

		if strings.HasPrefix(line, "IdentityFile") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "IdentityFile"))
			if !filepath.IsAbs(path) {
				return nil, fmt.Errorf("IdentityFile's path %s for host %s is not an absolute path", path, block.host)
			}
			block.identityFile = path
		}

		if strings.HasPrefix(line, "IdentitiesOnly") {
			yerOrNo := strings.TrimSpace(strings.TrimPrefix(line, "IdentitiesOnly"))
			switch yerOrNo {
			case "yes":
				block.identitiesOnly = true
			case "", "not":
				block.identitiesOnly = false
			default:
				return nil, fmt.Errorf("invalid value for IdentitiesOnly for host %s", yerOrNo)
			}
		}

		if strings.HasPrefix(line, "CertificateFile") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "CertificateFile"))
			if !filepath.IsAbs(path) {
				return nil, fmt.Errorf("CertificateFile's path %s for host %s is not an absolute path", path, block.host)
			}
		}

		if block.identityFile == "" && (block.identitiesOnly || block.certificateFile != "") {
			return nil, fmt.Errorf("IdentityFile not specified but IdentitiesOnly is yes or CertificateFile is specified for host %s", block.host)
		}
	}

	// Add the last host entry, if any
	if block.host != "" {
		blocks[block.host] = block
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return blocks, nil
}

func saveClientConfigFile(blocks map[string]clientConfigBlock, clientConfigPath string) error {
	var blockSlice []clientConfigBlock
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
		buf.WriteString(fmt.Sprintf("Host %s\n", block.host))
		buf.WriteString(fmt.Sprintf("    Hostname %s\n", block.hostName))
		buf.WriteString(fmt.Sprintf("    User %s\n", block.user))
		buf.WriteString(fmt.Sprintf("    Port %d\n", block.port))
		if block.identityFile != "" {
			buf.WriteString(fmt.Sprintf("    IdentityFile %s\n", block.identityFile))
			if block.identitiesOnly {
				buf.WriteString("    IdentitiesOnly yes\n")
			}
			if block.certificateFile != "" {
				buf.WriteString(fmt.Sprintf("    CertificateFile %s\n", block.certificateFile))
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
		domains[block.hostName] = name
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

	if clientConfigPath == "" {
		errs = append(errs, errors.New("empty string for path to user-specific SSH client configuration file")) 
		return errors.Join(errs...)
	}

	if !filepath.IsAbs(clientConfigPath) {
		errs = append(errs, fmt.Errorf("path to user-specific SSH client configuration file \"%s\" is not an absolute path", clientConfigPath))
		return errors.Join(errs...)
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
			block := clientConfigBlock{
				host:         host,
				hostName:     getSSHAddress(subject),
				user:         user,
				port:         subject.GetSSHPort(),
				identityFile: privateKeyPath,
			}
			if privateKeyPath != "" {
				block.identitiesOnly = true
				block.certificateFile = certificatePath
			}

			blocks[host] = block
			hosts = append(hosts, host)
		}
	} else {
		host := subject.GetHostname()
		block := clientConfigBlock{
			host:         host,
			hostName:     getSSHAddress(subject),
			user:         subject.GetSSHUser()[0],
			port:         subject.GetSSHPort(),
			identityFile: privateKeyPath,
		}

		if privateKeyPath != "" {
			block.identitiesOnly = true
			block.certificateFile = certificatePath
		}

		blocks[host] = block
		hosts = append(hosts, host)
	}

	if err := saveClientConfigFile(blocks, clientConfigPath); err != nil {
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

	paths := map[string]string{
		"user-specific SSH client configuration": clientConfigPath,
		"SSH private key":                        privateKeyPath,
		"SSH certificate":                        certificatePath,
	}

	for name, path := range paths {
		if path == "" {
			errs = append(errs, fmt.Errorf("empty path for %s file", name)) 
			continue
		}
	
		if !filepath.IsAbs(clientConfigPath) {
			errs = append(errs, fmt.Errorf("path to %s file \"%s\" is not an absolute path", name, clientConfigPath))
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
