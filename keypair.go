package sshman

type KeyPair struct {
	PublicKey          []byte
	PrivateKey         []byte
	PrivateKeyPassword []byte
}
