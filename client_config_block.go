package sshman

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/copartner6412/input/validate"
)

type ClientConfigBlock struct {
	ID              string
	User            string
	Address         string
	Port            uint16
	IdentityFile    string
	IdentitiesOnly  bool
	CertificateFile string
}

func LoadClientConfigBlocks(clientConfigFilePath string) ([]ClientConfigBlock, error) {
	file, err := os.Open(clientConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("error openning client config file: %w", err)
	}

	var block ClientConfigBlock
	var blocks []ClientConfigBlock

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasSuffix(line, "Host") {
			if block.ID != "" {
				blocks = append(blocks, block)
			}

			alias := strings.TrimSpace(strings.TrimPrefix(line, "Host"))
			block.ID = alias
		}

		if strings.HasPrefix(line, "HostName") {
			hostname := strings.TrimSpace(strings.TrimPrefix(line, "HostName"))
			err1 := validate.IP(hostname, "")
			err2 := validate.Domain(hostname, 0, 0)
			if err1 != nil && err2 != nil {
				return nil, fmt.Errorf("invalid address for host \"%s\": %w", block.ID, errors.Join(err1, err2))
			}
		}

		if strings.HasPrefix(line, "User") {
			block.User = strings.TrimSpace(strings.TrimPrefix(line, "User"))
		}

		if strings.HasPrefix(line, "Port") {
			portStr := strings.TrimSpace(strings.TrimPrefix(line, "Port"))
			portNum, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("error converting port to integer for host %s: %w", block.ID, err)
			}
			block.Port = uint16(portNum)
		}

		if strings.HasPrefix(line, "IdentityFile") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "IdentityFile"))
			if !filepath.IsAbs(path) {
				return nil, fmt.Errorf("IdentityFile's path %s for host %s is not an absolute path", path, block.ID)
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
				return nil, fmt.Errorf("CertificateFile's path %s for host %s is not an absolute path", path, block.ID)
			}
		}

		if block.IdentityFile == "" && (block.IdentitiesOnly || block.CertificateFile != "") {
			return nil, fmt.Errorf("IdentityFile not specified but IdentitiesOnly is yes or CertificateFile is specified for host %s", block.ID)
		}
	}

	// Add the last host entry, if any
	if block.ID != "" {
		blocks = append(blocks, block)
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return blocks, nil
}

func SaveClientConfigBlocks(clientConfigFilePath string, allBlocks []ClientConfigBlock) error {
	blocksByAlias := make(map[string]ClientConfigBlock)

	var aliases []string
	var buf bytes.Buffer

	for _, block := range allBlocks {
		aliases = append(aliases, block.ID)
		blocksByAlias[block.ID] = block
	}

	sort.Strings(aliases)
	for _, alias := range aliases {
		allBlocks = append(allBlocks, blocksByAlias[alias])
	}

	for _, block := range allBlocks {
		buf.WriteString(fmt.Sprintf("Host %s\n", block.ID))
		buf.WriteString(fmt.Sprintf("    Hostname %s\n", block.Address))
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

	err := os.WriteFile(clientConfigFilePath, buf.Bytes(), fs.FileMode(0644))
	if err != nil {
		return fmt.Errorf("error writing data to %s: %w", clientConfigFilePath, err)
	}

	return nil
}

func FindClientConfigBlocks(allBlocks []ClientConfigBlock, alias, user, address string) []ClientConfigBlock {
	var found []ClientConfigBlock

	if alias != "" && user != "" && address != "" {
		for _, block := range allBlocks {
			if block.ID == alias && block.User == user && block.Address == address {
				found = append(found, block)
			}
		}
	} else if alias != "" && user != "" && address == "" {
		for _, block := range allBlocks {
			if block.ID == alias && block.User == user {
				found = append(found, block)
			}
		}
	} else if alias != "" && user == "" && address != "" {
		for _, block := range allBlocks {
			if block.ID == alias && block.Address == address {
				found = append(found, block)
			}
		}
	} else if alias != "" && user == "" && address == "" {
		for _, block := range allBlocks {
			if block.ID == alias {
				found = append(found, block)
			}
		}
	} else if alias == "" && user != "" && address != "" {
		for _, block := range allBlocks {
			if block.User == user && block.Address == address {
				found = append(found, block)
			}
		}
	} else if alias == "" && user != "" && address == "" {
		for _, block := range allBlocks {
			if block.User == user {
				found = append(found, block)
			}
		}
	} else if alias == "" && user == "" && address != "" {
		for _, block := range allBlocks {
			if block.Address == address {
				found = append(found, block)
			}
		}
	} else {
		return nil
	}

	return found
}

func DeleteClientConfigBlock(allBlocks []ClientConfigBlock, deleteBlock ClientConfigBlock) []ClientConfigBlock {
	for i, block := range allBlocks {
		if block.User == deleteBlock.User && block.Address == deleteBlock.Address {
			allBlocks = append(allBlocks[:i], allBlocks[i+1:]...)
		}
	}

	return allBlocks
}

func AddClientConfigBlock(allBlocks []ClientConfigBlock, addBlock ClientConfigBlock) ([]ClientConfigBlock, error) {
	if err := ValidateClientConfigBlock(addBlock); err != nil {
		return nil, fmt.Errorf("invalid client config block: %w", err)
	}

	found := append(FindClientConfigBlocks(allBlocks, "", addBlock.User, addBlock.Address), FindClientConfigBlocks(allBlocks, addBlock.ID, "", "")...)

	for _, block := range found {
		allBlocks = DeleteClientConfigBlock(allBlocks, block)
	}

	return allBlocks, nil
}

func ValidateClientConfigBlock(block ClientConfigBlock) error {
	var errs []error

	err1 := validate.IP(block.Address, "")
	err2 := validate.Domain(block.Address, 0, 0)
	if err1 != nil && err2 != nil {
		errs = append(errs, fmt.Errorf("invalid address \"%s\"", block.Address))
	}

	if block.IdentityFile == "" {
		errs = append(errs, errors.New("empty IdentityFile path"))
	} else if !filepath.IsAbs(block.IdentityFile) {
		errs = append(errs, fmt.Errorf("IdentityFile path \"%s\" not an absolute path", block.IdentityFile))
	}

	if block.CertificateFile == "" {
		errs = append(errs, errors.New("empty CertificateFile path"))
	} else if !filepath.IsAbs(block.CertificateFile) {
		errs = append(errs, fmt.Errorf("CertificateFile path \"%s\" not an absolute path", block.CertificateFile))
	}

	if block.IdentityFile == "" && block.CertificateFile != "" {
		errs = append(errs, errors.New("CertificateFile path is specified while IdentityFile path is empty"))
	}

	if block.IdentitiesOnly && block.IdentityFile == "" {
		errs = append(errs, errors.New("IdentitiesOnly is set to true while IdentityFile path is empty"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
