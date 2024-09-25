package sshman_test

import (
	"crypto"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/copartner6412/input/pseudorandom"
	"github.com/copartner6412/sshman"
	"golang.org/x/crypto/ssh"
)

const (
	minDuration time.Duration = 1 * time.Second
	maxDuration time.Duration = 30 * 365 * 24 * time.Hour // 30 years
)

type mockSubject struct {
	user     string
	domain   string
	hostname string
	ipv4     string
	ipv6     string
}

func (s mockSubject) GetUser() []string {
	return []string{s.user}
}

func (s mockSubject) GetDomain() []string {
	return []string{s.domain}
}

func (s mockSubject) GetHostname() string {
	return s.hostname
}

func (s mockSubject) GetIPv4() []string {
	return []string{"127.0.0.1", s.ipv4}
}

func (s mockSubject) GetIPv6() []string {
	return []string{s.ipv6}
}

type generateSSHInput struct {
	subject   mockSubject
	ca        sshman.KeyPair
	comment   string
	duration  time.Duration
	algorithm sshman.Algorithm
	password  string
}

type issueSSHInput struct {
	ca          sshman.KeyPair
	publicKey   ssh.PublicKey
	privateKey  crypto.PrivateKey
	certificate *ssh.Certificate
	comment     string
	password    string
}

func pseudorandomInputForGenerateSSH(r *rand.Rand) (generateSSHInput, error) {
	var errs []error

	subject, comment, err := pseudorandomSubjectComment(r)
	if err != nil {
		errs = append(errs, fmt.Errorf("error generating pseudo-random Subject and comment: %v", err))
	}

	ca, err := pseudorandomCA(r)
	if err != nil {
		errs = append(errs, fmt.Errorf("error generating pseudo-random CA: %v", err))
	}

	password, err := pseudorandom.PasswordFor(r, pseudorandom.PasswordProfileSSHKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("error generating pseudo-random password: %v", err))
	}

	validDuration, err := pseudorandom.Duration(r, minDuration, maxDuration)
	if err != nil {
		errs = append(errs, fmt.Errorf("error generating pseudo-random duration: %v", err))
	}

	algorithm := pseudorandomAlgorithm(r)

	if len(errs) > 0 {
		return generateSSHInput{}, errors.Join(errs...)
	}

	return generateSSHInput{
		subject:   subject,
		ca:        ca,
		comment:   comment,
		duration:  validDuration,
		algorithm: algorithm,
		password:  password,
	}, nil
}

func pseudorandomInputForIssueSSH(r *rand.Rand, certificateType sshman.CertificateType) (issueSSHInput, error) {

	ca, err := pseudorandomCA(r)
	if err != nil {
		return issueSSHInput{}, fmt.Errorf("error generating pseudo-random CA: %v", err)
	}

	algorithm := pseudorandomAlgorithm(r)

	comment, err := pseudorandom.String(r, 1, 256, true)
	if err != nil {
		return issueSSHInput{}, fmt.Errorf("error generating pseudo-random comment: %v", err)
	}

	password, err := pseudorandom.PasswordFor(r, pseudorandom.PasswordProfileSSHKey)
	if err != nil {
		return issueSSHInput{}, fmt.Errorf("error generating pseudo-random password for SSH key: %v", err)
	}

	keyPair, err := sshman.GenerateKeyPair(algorithm, comment, password)
	if err != nil {
		return issueSSHInput{}, fmt.Errorf("error generating a random CA: %v", err)
	}

	privateKey, err := ssh.ParseRawPrivateKeyWithPassphrase(keyPair.PrivateKey, keyPair.PrivateKeyPassword)
	if err != nil {
		return issueSSHInput{}, fmt.Errorf("error parsing private key with password to raw crypto.PrivatKey: %v", err)
	}

	publicKey, _, err := sshman.ParseKeyPair(keyPair)
	if err != nil {
		return issueSSHInput{}, fmt.Errorf("error parsing key pair: %v", err)
	}

	serial, err := pseudorandom.BigInteger(r, 65, 128)
	if err != nil {
		return issueSSHInput{}, fmt.Errorf("error generating pseudo-random serial number for SSH certificate: %v", err)
	}

	keyId, err := pseudorandom.String(r, 1, 256, true)
	if err != nil {
		return issueSSHInput{}, fmt.Errorf("error generating pseudo-random key ID for SSH certificate: %v", err)
	}

	duration, err := pseudorandom.Duration(r, 5*time.Second, 30*365*24*time.Hour)
	if err != nil {
		return issueSSHInput{}, fmt.Errorf("error generating pseudo-random duration for SSH certificate: %v", err)
	}

	certificate := ssh.Certificate{
		Key:         publicKey,
		Serial:      serial.Uint64(),
		KeyId:       keyId,
		ValidAfter:  uint64(time.Now().Unix()),
		ValidBefore: uint64(time.Now().Add(duration).Unix()),
	}

	if certificateType == sshman.HostCert {
		certificate.CertType = ssh.HostCert
	} else {
		certificate.CertType = ssh.UserCert
		certificate.ValidPrincipals = []string{pseudorandom.Username(r, false, true, nil)}
	}

	return issueSSHInput{
		ca:          ca,
		publicKey:   publicKey,
		privateKey:  privateKey,
		certificate: &certificate,
		comment:     comment,
		password:    password,
	}, nil

}

func pseudorandomSubjectComment(r *rand.Rand) (mockSubject, string, error) {
	var errs []error

	user := pseudorandom.Username(r, false, true, nil)

	domain, err := pseudorandom.Domain(r, 0, 0)
	if err != nil {
		errs = append(errs, err)
	}

	hostname, err := pseudorandom.LinuxHostname(r, 0, 0)
	if err != nil {
		errs = append(errs, err)
	}

	ipv4, err := pseudorandom.IPv4(r, "")
	if err != nil {
		errs = append(errs, err)
	}

	ipv6, err := pseudorandom.IPv6(r, "")
	if err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return mockSubject{}, "", errors.Join(errs...)
	}

	var comments []string
	host := append([]string{}, domain, hostname, ipv4.String(), ipv6.String())
	for _, h := range host {
		comments = append(comments, user+"@"+h)
	}
	comment := strings.Join(comments, " ")

	return mockSubject{
		user:     user,
		domain:   domain,
		hostname: hostname,
		ipv4:     ipv4.String(),
		ipv6:     ipv6.String(),
	}, comment, nil
}

func pseudorandomAlgorithm(r *rand.Rand) sshman.Algorithm {
	algorithm := sshman.Algorithm(r.IntN(9))
	if algorithm == sshman.AlgorithmECDSAP224 || algorithm == sshman.AlgorithmRSA1024 {
		return sshman.AlgorithmED25519
	}

	return algorithm
}

func pseudorandomCA(r *rand.Rand) (sshman.KeyPair, error) {
	caAlgorithm := pseudorandomAlgorithm(r)

	comment, err := pseudorandom.Password(r, 3, 128, true, true, true, false)
	if err != nil {
		return sshman.KeyPair{}, fmt.Errorf("error generating pseudo-random comment: %v", err)
	}

	password, err := pseudorandom.PasswordFor(r, pseudorandom.PasswordProfileSSHCAKey)
	if err != nil {
		return sshman.KeyPair{}, fmt.Errorf("error generating pseudo-random password: %v", err)
	}

	ca, err := sshman.GenerateKeyPair(caAlgorithm, comment, password)
	if err != nil {
		return sshman.KeyPair{}, fmt.Errorf("error generating random key pair: %v", err)
	}

	return ca, nil
}
