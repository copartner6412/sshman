package sshman

import (
	"fmt"

	"github.com/copartner6412/input/random"
	"golang.org/x/crypto/ssh"
)

func GenerateKeyPair(algorithm Algorithm, comment string, password string) (KeyPair, error) {
	publicKey, privateKey, err := random.KeyPair(random.Algorithm(algorithm))
	if err != nil {
		return KeyPair{}, fmt.Errorf("error generating a random key pair: %w", err)
	}

	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("error converting crypto public key to SSH public key: %w", err)
	}

	privateKeyPEMBytes, err := encodePrivateKeyToPEMBytes(privateKey, comment, password)
	if err != nil {
		return KeyPair{}, fmt.Errorf("error encoding private key: %w", err)
	}

	keyPair := KeyPair{
		PublicKey:          ssh.MarshalAuthorizedKey(sshPublicKey),
		PrivateKey:         privateKeyPEMBytes,
		PrivateKeyPassword: []byte(password),
	}

	if _, _, err := ParseKeyPair(keyPair); err != nil {
		return KeyPair{}, fmt.Errorf("invalid key pair generated: %w", err)
	}

	return keyPair, nil
}
