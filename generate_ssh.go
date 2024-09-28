package sshman

import (
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/copartner6412/input/random"
	"github.com/copartner6412/input/validate"
	"golang.org/x/crypto/ssh"
)

const (
	minSSHCertificateSerialBitSize uint = 32
	maxSSHCertificateSerialBitSize uint = 64
	ssCertificateNonceBytes        uint = 16
)

const (
	minDurationAllowed time.Duration = 1 * time.Second
	maxDurationAllowed time.Duration = 30 * 365 * 24 * time.Hour // 30 years
)

// GenerateSSH creates an SSH key pair and certificate based on the provided parameters.
// It returns an SSH struct containing the generated keys and certificate, or an error if the process fails.
func GenerateSSH(subject Subject, ca KeyPair, certificateType CertificateType, algorithm Algorithm, validFor time.Duration, password []byte) (*SSH, error) {
	err := validateGenerateSSHInput(subject, ca, algorithm, validFor, password)
	if err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	_, caPrivateKey, err := ca.Parse()
	if err != nil {
		return nil, fmt.Errorf("error parsing CA: %w", err)
	}

	// Generate key pair
	publicKey, privateKey, err := random.KeyPair(random.Algorithm(algorithm))
	if err != nil {
		return nil, fmt.Errorf("error generating key pair: %w", err)
	}

	comment := generateCommentForSubject(subject)

	// Create SSH public key
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("error creating SSH public key: %w", err)
	}

	// Prepare certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serial, err := random.BigInteger(minSSHCertificateSerialBitSize, maxSSHCertificateSerialBitSize)
	if err != nil {
		return nil, fmt.Errorf("error generating a serial number for SSH certificate: %w", err)
	}

	certificate := &ssh.Certificate{
		Key:         sshPublicKey,
		Serial:      serial.Uint64(),
		CertType:    getCertType(certificateType),
		KeyId:       getKeyID(subject, certificateType),
		ValidAfter:  uint64(notBefore.Unix()),
		ValidBefore: uint64(notAfter.Unix()),
	}

	if certificateType == UserCert {
		certificate.ValidPrincipals = getPrincipals(subject, certificateType)
	}

	if err := certificate.SignCert(rand.Reader, caPrivateKey); err != nil {
		return nil, fmt.Errorf("error signing certificate: %w", err)
	}

	// Encode private key
	privateKeyPEMBytes, err := encodePrivateKeyToPEMBytes(privateKey, comment, password)
	if err != nil {
		return nil, fmt.Errorf("error encoding private key: %w", err)
	}

	result := &SSH{
		PublicKey:          ssh.MarshalAuthorizedKey(sshPublicKey),
		PrivateKey:         privateKeyPEMBytes,
		Certificate:        ssh.MarshalAuthorizedKey(certificate),
		PrivateKeyPassword: password,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
	}

	if _, _, _, err := result.Parse(); err != nil {
		return nil, fmt.Errorf("generated invalid SSH asset: %w", err)
	}

	return result, nil
}

func validateGenerateSSHInput(subject Subject, ca KeyPair, algorithm Algorithm, validFor time.Duration, password []byte) error {
	var errs []error

	if err := ValidateSubject(subject); err != nil {
		errs = append(errs, fmt.Errorf("invalid subject: %w", err))
	}

	if _, _, err := ca.Parse(); err != nil {
		errs = append(errs, fmt.Errorf("error parsing CA: %w", err))
	}

	if err := validateAlgorithm(algorithm, []Algorithm{AlgorithmECDSAP224, AlgorithmRSA1024}); err != nil {
		errs = append(errs, fmt.Errorf("invalid algorithm: %w", err))
	}

	if err := validate.Duration(validFor, minDurationAllowed, maxDurationAllowed); err != nil {
		errs = append(errs, fmt.Errorf("invalid duration: %w", err))
	}

	if err := validate.PasswordFor(string(password), validate.PasswordProfileSSHKey); err != nil {
		errs = append(errs, fmt.Errorf("invalid password: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func validateAlgorithm(algorithm Algorithm, weaks []Algorithm) error {
	for _, weak := range weaks {
		if algorithm == weak {
			return fmt.Errorf("weak algorithm: %s", algorithm.String())
		}
	}

	if algorithm > 8 {
		return fmt.Errorf("unsupport algorithm type")
	}

	return nil
}

func generateCommentForSubject(subject Subject) string {
	users := subject.GetSSHUser()
	hosts := []string{}
	comments := []string{}

	hostname := subject.GetHostname()

	if hostname != "" {
		hosts = []string{hostname}
	}

	hosts = append(hosts, subject.GetDomain()...)
	hosts = append(hosts, subject.GetIPv4()...)
	hosts = append(hosts, subject.GetIPv6()...)

	for _, user := range users {
		for _, host := range hosts {
			comments = append(comments, user+"@"+host)
		}
	}

	return strings.Join(comments, "")
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
