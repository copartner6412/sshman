package sshman

import (
	"crypto"
	"encoding/pem"
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

// encodePrivateKey encodes the private key in PEM format, optionally encrypting it with a password.
func encodePrivateKeyToPEMBytes(privateKey crypto.PrivateKey, comment string, password []byte) ([]byte, error) {
	var pemBlock *pem.Block
	var err error

	switch password {
	case nil:
		pemBlock, err = ssh.MarshalPrivateKey(privateKey, comment)
		if err != nil {
			return nil, fmt.Errorf("error marshaling private key: %w", err)
		}
	default:
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, comment, password)
		if err != nil {
			return nil, fmt.Errorf("error marshaling private key with password: %w", err)
		}
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// getCertType returns the appropriate certificate type based on the role.
func getCertType(CertType CertificateType) uint32 {
	if CertType == HostCert {
		return ssh.HostCert
	}

	return ssh.UserCert
}

// getKeyID generates a key ID based on the subject and role.
func getKeyID(subject Subject, certType CertificateType) string {
	var host string

	hostname := subject.GetHostname()
	domains := subject.GetDomain()
	ipv4s := subject.GetIPv4()
	ipv6s := subject.GetIPv6()

	if hostname != "" {
		host = hostname
	} else if domains != nil {
		host = domains[0]
	} else if ipv4s != nil {
		host = ipv4s[0]
	} else {
		host = ipv6s[0]
	}

	if certType == HostCert {
		return fmt.Sprintf("host_%s", host)
	}

	return fmt.Sprintf("user_%s", subject.GetSSHUser()[0])
}

// getPrincipals returns the appropriate principals based on the subject and role.
func getPrincipals(subject Subject, certType CertificateType) []string {
	if certType == HostCert {
		return nil
	}

	users := subject.GetSSHUser()
	hosts := []string{}
	principals := []string{}

	principals = append(principals, users...)

	hostname := subject.GetHostname()

	if hostname != "" {
		hosts = []string{hostname}
	}

	hosts = append(hosts, subject.GetDomain()...)
	hosts = append(hosts, subject.GetIPv4()...)
	hosts = append(hosts, subject.GetIPv6()...)

	principals = append(principals, hosts...)

	return principals
}
