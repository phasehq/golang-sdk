package crypto

import (
	// For generating cryptographic random bytes
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jamesruan/sodium" // For sodium operations
	"golang.org/x/crypto/blake2b"
	// For NaCl operations in Go
)

// RandomKeyPair generates a random key pair
func RandomKeyPair() (sodium.KXKP, error) {
	kp := sodium.MakeKXKP()
	return kp, nil
}

// ClientSessionKeys generates client session keys given a client's ephemeral keypair and the recipient's public key.
func ClientSessionKeys(kp sodium.KXKP, recipientPublicKey []byte) (*sodium.KXSessionKeys, error) {
	recipientPubKey := sodium.KXPublicKey{Bytes: recipientPublicKey}
	sessionKeys, err := kp.ClientSessionKeys(recipientPubKey)
	if err != nil {
		return nil, err
	}
	return sessionKeys, nil
}

// ServerSessionKeys generates server session keys given the server's keypair and the client's public key.
func ServerSessionKeys(kp sodium.KXKP, clientPublicKey []byte) (*sodium.KXSessionKeys, error) {
    clientPubKey := sodium.KXPublicKey{Bytes: clientPublicKey}
    sessionKeys, err := kp.ServerSessionKeys(clientPubKey)
    if err != nil {
        return nil, err
    }
    return sessionKeys, nil
}

// encryptRaw encrypts plaintext using the given key with XChaCha20-Poly1305.
func encryptRaw(plaintext string, key sodium.KXSessionKey) ([]byte, error) {
	sKey := sodium.MakeAEADCPKey() // Initialize the AEADCPKey
    var nonce sodium.AEADCPNonce
    sodium.Randomize(&nonce) // Randomize nonce

    ad := sodium.Bytes(nil) // No additional data
    plaintextBytes := sodium.Bytes(plaintext)
    ciphertext := plaintextBytes.AEADCPEncrypt(ad, nonce, sKey)

    // Directly use the Bytes field for the nonce
    return append(nonce.Bytes, ciphertext...), nil
}

// decryptRaw decrypts the combined nonce and ciphertext using the given key.
func decryptRaw(combinedCt []byte, key sodium.KXSessionKey) ([]byte, error) {
    var nonce sodium.AEADCPNonce
    nonceSize := nonce.Size()
    if len(combinedCt) < nonceSize {
        return nil, fmt.Errorf("combinedCt too short")
    }

    // Copy the nonce bytes directly
    nonce.Bytes = make([]byte, nonceSize)
    copy(nonce.Bytes, combinedCt[:nonceSize])

    ciphertext := combinedCt[nonceSize:]
    sKey := sodium.MakeAEADCPKey()

    plaintext, err := sodium.Bytes(ciphertext).AEADCPDecrypt(sodium.Bytes(nil), nonce, sKey)
    if err != nil {
        return nil, err
    }
    return plaintext, nil
}

// encryptB64 encrypts the plaintext using the given key and returns a base64 encoded string.
func encryptB64(plaintext string, key sodium.KXSessionKey) (string, error) {
    rawCt, err := encryptRaw(plaintext, key)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(rawCt), nil
}

// decryptB64 decrypts a base64 encoded ciphertext using the given key.
// It returns the original plaintext.
func decryptB64(b64Ct string, key sodium.KXSessionKey) (string, error) {
    ct, err := base64.StdEncoding.DecodeString(b64Ct)
    if err != nil {
        return "", err
    }
    plaintextBytes, err := decryptRaw(ct, key)
    if err != nil {
        return "", err
    }
    return string(plaintextBytes), nil
}


// encryptAsymmetric takes plaintext and a recipient's public key in hex, encrypts the plaintext, and returns a formatted ciphertext.
func EncryptAsymmetric(plaintext, publicKeyHex string) (string, error) {
	recipientPubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", err
	}

	// Generate ephemeral key pair
	kp, err := RandomKeyPair()
	if err != nil {
		return "", err
	}

	// Generate session keys
	sessionKeys, err := ClientSessionKeys(kp, recipientPubKeyBytes)
	if err != nil {
		return "", err
	}

	// Encrypt the plaintext using the session TX key
	ciphertext, err := encryptB64(plaintext, sessionKeys.Tx)
	if err != nil {
		return "", err
	}

	// Return the formatted ciphertext
	return fmt.Sprintf("ph:v1:%s:%s", hex.EncodeToString(kp.PublicKey.Bytes), ciphertext), nil
}

// decryptAsymmetric decrypts a ciphertext string using the private key and the sender's public key.
func DecryptAsymmetric(ciphertextString, privateKeyHex, publicKeyHex string) (string, error) {
    segments := strings.Split(ciphertextString, ":")
    if len(segments) != 4 {
        return "", errors.New("invalid ciphertext format")
    }
    //version := segments[1] // This can be used to handle different versions of the payload format
    version := segments[1]
    ephemeralPublicKeyHex := segments[2]
    ciphertextB64 := segments[3]

    if version != "v1" {   // This is a simplistic check. Expand according to actual version handling needs.
        return "", fmt.Errorf("unsupported version: %s", version)
    }
    
    // Decode hex values to bytes
    ephemeralPublicKeyBytes, err := hex.DecodeString(ephemeralPublicKeyHex)
    if err != nil {
        return "", err
    }
    privateKeyBytes, err := hex.DecodeString(privateKeyHex)
    if err != nil {
        return "", err
    }
    publicKeyBytes, err := hex.DecodeString(publicKeyHex)
    if err != nil {
        return "", err
    }

    // Generate key pair for server
    kp := sodium.KXKP{
        PublicKey: sodium.KXPublicKey{Bytes: publicKeyBytes},
        SecretKey: sodium.KXSecretKey{Bytes: privateKeyBytes},
    }

    // Generate session keys
    sessionKeys, err := ServerSessionKeys(kp, ephemeralPublicKeyBytes)
    if err != nil {
        return "", err
    }

    // Decode the base64 ciphertext
    ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
    if err != nil {
        return "", err
    }

    // Decrypt the ciphertext (Placeholder: Replace with actual decryption method)
    plaintext, err := decryptB64(string(ciphertext), sessionKeys.Rx)
    if err != nil {
        return "", err
    }

    return plaintext, nil
}

// Blake2bDigest generates a BLAKE2b hash of the input string with a salt.
func Blake2bDigest(inputStr, salt string) (string, error) {
    hashSize := 32 // 32 bytes (256 bits)

    // The key argument is used as a salt
    h, err := blake2b.New(hashSize, []byte(salt))
    if err != nil {
        return "", err
    }

    _, err = h.Write([]byte(inputStr))
    if err != nil {
        return "", err
    }

    hashed := h.Sum(nil)
    hexEncoded := hex.EncodeToString(hashed)
    return hexEncoded, nil
}

// xorBytes computes the XOR of two byte slices.
func xorBytes(a, b []byte) []byte {
    n := len(a)
    if len(b) > n {
        n = len(b)
    }
    result := make([]byte, n)
    for i := 0; i < n; i++ {
        result[i] = a[i] ^ b[i]
    }
    return result
}

// reconstructSecret reconstructs a secret given an array of hex-encoded shares.
func reconstructSecret(shares []string) (string, error) {
    var result []byte
    for _, share := range shares {
        shareBytes, err := hex.DecodeString(share)
        if err != nil {
            return "", err
        }
        if result == nil {
            result = make([]byte, len(shareBytes))
        }
        result = xorBytes(result, shareBytes)
    }
    return hex.EncodeToString(result), nil
}
