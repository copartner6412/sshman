package sshman

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"
)

func LoadPublicKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening public key file in %s: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}

	// Ensure consistent line endings (use LF) and remove any trailing whitespace.
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.TrimSpace(data)

	if _, _, _, _, err := ssh.ParseAuthorizedKey(data); err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	return data, nil
}
