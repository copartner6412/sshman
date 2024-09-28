package sshman

import (
	"fmt"
	"io"

	"github.com/copartner6412/input/random"
	"golang.org/x/crypto/ssh"
)

func GenerateKeyPair(randomness io.Reader, algorithm Algorithm, comment string, password []byte) (*KeyPair, error) {
	publicKey, privateKey, err := random.KeyPair(randomness, random.Algorithm(algorithm))
	if err != nil {
		return nil, fmt.Errorf("error generating a random key pair: %w", err)
	}

	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("error converting crypto public key to SSH public key: %w", err)
	}

	privateKeyPEMBytes, err := encodePrivateKeyToPEMBytes(privateKey, comment, password)
	if err != nil {
		return nil, fmt.Errorf("error PEM-encoding private key: %w", err)
	}

	keyPair := &KeyPair{
		PublicKey:          ssh.MarshalAuthorizedKey(sshPublicKey),
		PrivateKey:         privateKeyPEMBytes,
		PrivateKeyPassword: password,
	}

	if _, _, err := keyPair.Parse(); err != nil {
		return nil, fmt.Errorf("invalid key pair generated: %w", err)
	}

	return keyPair, nil
}
