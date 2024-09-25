package sshman

import "time"

type SSH struct {
	PublicKey          []byte
	PrivateKey         []byte
	Certificate        []byte
	PrivateKeyPassword []byte
	NotBefore          time.Time
	NotAfter           time.Time
}
