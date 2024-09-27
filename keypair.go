package sshman

import "bytes"

type KeyPair struct {
	PublicKey          []byte
	PrivateKey         []byte
	PrivateKeyPassword []byte
}

func (k *KeyPair) Destroy() {
	k.PublicKey = nil
	k.PrivateKey = nil
	k.PrivateKeyPassword = nil
}

func (k *KeyPair) IsZero() bool {
	return len(k.PublicKey) == 0 &&
		len(k.PrivateKey) == 0 &&
		len(k.PrivateKeyPassword) == 0
}

func (k *KeyPair) Equal(keyPair KeyPair) bool {
	return bytes.Equal(k.PublicKey, keyPair.PublicKey) &&
		bytes.Equal(k.PrivateKey, k.PrivateKey) &&
		bytes.Equal(k.PrivateKeyPassword, keyPair.PrivateKeyPassword)
}
