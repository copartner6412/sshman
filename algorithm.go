package sshman

// Algorithm defines the supported key generation algorithms.
type Algorithm int

// List of supported algorithms for key generation.
const (
	AlgorithmUntyped Algorithm = iota
	AlgorithmED25519
	AlgorithmECDSAP521
	AlgorithmECDSAP384
	AlgorithmECDSAP256
	AlgorithmECDSAP224
	AlgorithmRSA4096
	AlgorithmRSA2048
	AlgorithmRSA1024
)

var algorithmString = map[Algorithm]string{
	AlgorithmUntyped:   "untyped",
	AlgorithmED25519:   "ED25519",
	AlgorithmECDSAP521: "ECDSA P521",
	AlgorithmECDSAP384: "ECDSA P384",
	AlgorithmECDSAP256: "ECDSA P256",
	AlgorithmECDSAP224: "ECDSA P224",
	AlgorithmRSA4096:   "RSA 4096",
	AlgorithmRSA2048:   "RSA 2048",
	AlgorithmRSA1024:   "RSA 1024",
}

func (a Algorithm) String() string {
	return algorithmString[a]
}
