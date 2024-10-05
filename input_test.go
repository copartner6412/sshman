package sshman_test

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/copartner6412/input/pseudorandom"
	"github.com/copartner6412/sshman"
)

const (
	minDuration time.Duration = 1 * time.Second
	maxDuration time.Duration = 20 * 365 * 24 * time.Hour // 20 years
)

type testInput struct {
	ca        *sshman.KeyPair
	duration  time.Duration
	algorithm sshman.Algorithm
	comment   string
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

	ca, err := sshman.GenerateKeyPair(cryptorand.Reader, caAlgorithm, comment, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("error generating random key pair: %v", err)
	}

	return ca, nil
}
