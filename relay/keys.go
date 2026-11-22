package relay

import (
	"fmt"
)

// The sizes of libsignal's serialized public keys and signatures. The server checks only these: it can't verify an
// XEdDSA signature over a prekey without libsignal, so the phones check the signatures against the identity key they
// got in the pairing QR code.
const (
	// An EC (Curve25519) public key: the type byte 0x05 and 32 bytes. Identity keys and EC prekeys.
	ECKeyBytes = 33
	ecKeyType  = 0x05
	// A Kyber (ML-KEM 1024) public key: a type byte and 1568 bytes.
	KyberKeyBytes = 1569
	// An XEdDSA signature.
	SignatureBytes = 64
	// MaxRegistrationID is the highest registration id libsignal makes (14 bits, 0 not used).
	MaxRegistrationID = 16380
	// MaxKeyID is the highest prekey id the apps use (24 bits, as Signal's).
	MaxKeyID = 1<<24 - 1
	// MaxOneTimeUpload is how many one-time prekeys of each kind one uploadPrekeys may add, and MaxOneTimeHeld how many
	// the server keeps for a device.
	MaxOneTimeUpload = 100
	MaxOneTimeHeld   = 500
	// RefillBelow is when a device uploads more one-time prekeys (prekeyCount.refillBelow).
	RefillBelow = 20
)

// CheckECKey refuses what isn't a serialized EC public key.
func CheckECKey(what string, key []byte) error {
	if len(key) != ECKeyBytes || key[0] != ecKeyType {
		return fmt.Errorf("%s isn't an EC public key: %d bytes, want %d starting with 0x05", what, len(key), ECKeyBytes)
	}
	return nil
}

// CheckKyberKey refuses what isn't a serialized Kyber 1024 public key.
func CheckKyberKey(what string, key []byte) error {
	if len(key) != KyberKeyBytes {
		return fmt.Errorf("%s isn't a Kyber 1024 public key: %d bytes, want %d", what, len(key), KyberKeyBytes)
	}
	return nil
}

// CheckSignature refuses what isn't an XEdDSA signature.
func CheckSignature(what string, signature []byte) error {
	if len(signature) != SignatureBytes {
		return fmt.Errorf("the signature of %s is %d bytes, want %d", what, len(signature), SignatureBytes)
	}
	return nil
}

// CheckKeyID refuses a prekey id out of range.
func CheckKeyID(what string, id int) error {
	if id < 0 || id > MaxKeyID {
		return fmt.Errorf("the id of %s is %d, want 0 to %d", what, id, MaxKeyID)
	}
	return nil
}
