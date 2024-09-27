package sshman

import (
	"bytes"
	"time"
)

type SSH struct {
	PublicKey          []byte
	PrivateKey         []byte
	Certificate        []byte
	PrivateKeyPassword []byte
	NotBefore          time.Time
	NotAfter           time.Time
}

func (s *SSH) Destroy() {
	s.PublicKey = nil
	s.PrivateKey = nil
	s.Certificate = nil
	s.PrivateKeyPassword = nil
	s.NotBefore = time.Time{}
	s.NotAfter = time.Time{}
}

func (s *SSH) IsZero() bool {
	return len(s.PublicKey) == 0 &&
		len(s.PrivateKey) == 0 &&
		len(s.PrivateKeyPassword) == 0 &&
		len(s.Certificate) == 0 &&
		s.NotBefore.IsZero() &&
		s.NotAfter.IsZero()
}

func (s *SSH) Equal(sshAsset SSH) bool {
	return bytes.Equal(s.PublicKey, sshAsset.PublicKey) &&
		bytes.Equal(s.PrivateKey, sshAsset.PrivateKey) &&
		bytes.Equal(s.Certificate, sshAsset.Certificate) &&
		bytes.Equal(s.PrivateKeyPassword, sshAsset.PrivateKeyPassword) &&
		s.NotBefore.Equal(sshAsset.NotBefore) &&
		s.NotBefore.Equal(sshAsset.NotAfter)
}
