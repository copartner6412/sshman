package sshman_test

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/copartner6412/input/pseudorandom"
	"github.com/copartner6412/sshman"
)

const (
	minDuration time.Duration = 1 * time.Second
	maxDuration time.Duration = 20 * 365 * 24 * time.Hour // 20 years
)

type mockSubject struct {
	user     string
	port     uint16
	domain   string
	hostname string
	ipv4     string
	ipv6     string
}

func (s mockSubject) GetSSHUser() []string {
	return []string{s.user}
}

func (s mockSubject) GetSSHPort() uint16 {
	return s.port
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

type testInput struct {
	ca        *sshman.KeyPair
	duration  time.Duration
	algorithm sshman.Algorithm
	password  []byte
}

func pseudorandomTestInput(r *rand.Rand) (testInput, error) {
	var errs []error

	ca, err := pseudorandomCA(r)
	if err != nil {
		errs = append(errs, fmt.Errorf("error generating pseudo-random CA: %v", err))
	}

	algorithm := pseudorandomAlgorithm(r)

	validDuration, err := pseudorandom.Duration(r, minDuration, maxDuration)
	if err != nil {
		errs = append(errs, fmt.Errorf("error generating pseudo-random duration: %v", err))
	}

	password, err := pseudorandom.PasswordFor(r, pseudorandom.PasswordProfileSSHKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("error generating pseudo-random password: %v", err))
	}

	if len(errs) > 0 {
		return testInput{}, errors.Join(errs...)
	}

	return testInput{
		ca:        ca,
		algorithm: algorithm,
		duration:  validDuration,
		password:  []byte(password),
	}, nil
}

func pseudorandomSubjectComment(r *rand.Rand) (mockSubject, string, error) {
	var errs []error

	user := pseudorandom.Username(r, false, true, nil)

	port := pseudorandom.PortPrivate(r)

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
		port:     port,
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

func pseudorandomCA(r *rand.Rand) (*sshman.KeyPair, error) {
	caAlgorithm := pseudorandomAlgorithm(r)

	comment, err := pseudorandom.Password(r, 3, 128, true, true, true, false)
	if err != nil {
		return nil, fmt.Errorf("error generating pseudo-random comment: %v", err)
	}

	password, err := pseudorandom.PasswordFor(r, pseudorandom.PasswordProfileSSHCAKey)
	if err != nil {
		return nil, fmt.Errorf("error generating pseudo-random password: %v", err)
	}

	reader := pseudorandom.New(r)

	ca, err := sshman.GenerateKeyPair(reader, caAlgorithm, comment, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("error generating random key pair: %v", err)
	}

	return ca, nil
}
