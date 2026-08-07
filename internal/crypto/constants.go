package crypto

const (
	AlgorithmIDRsaOaep256 = 0x01
	AlgorithmIDMlKem1024  = 0x02

	EncapsulationSizeKyber = 1568
	EncapsulationSizeRsa   = 512

	IvLength          = 12
	MaxVersionLength  = 64
	MaxSpkiHeaderSize = 128

	SessionIdentity = "valid-session-key"

	AesKeyLength     = 32
	Pbkdf2Iterations = 100000
	Pbkdf2KeyLength  = 32
)
