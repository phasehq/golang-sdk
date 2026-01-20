package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/phasehq/golang-sdk/phase/network"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// X25519 key pair for key exchange.
type KeyPair struct {
	PublicKey [32]byte
	SecretKey [32]byte
}

// SessionKeys for XChaCha20-Poly1305 encryption/decryption.
type SessionKeys struct {
	Rx [32]byte // Rx key
	Tx [32]byte // Tx key
}

// Ephemeral for X25519 key exchange.
func RandomKeyPair() (KeyPair, error) {
	var secret, public [32]byte

	// Generate random secret key
	if _, err := rand.Read(secret[:]); err != nil {
		return KeyPair{}, fmt.Errorf("failed to generate random key: %w", err)
	}

	// Derive pk from sk key
	curve25519.ScalarBaseMult(&public, &secret)

	return KeyPair{PublicKey: public, SecretKey: secret}, nil
}

// ClientSessionKeys generates client session keys given a client's keypair and the server's public key.
func ClientSessionKeys(kp KeyPair, serverPublicKey []byte) (SessionKeys, error) {
	if len(serverPublicKey) != 32 {
		return SessionKeys{}, fmt.Errorf("server public key must be 32 bytes, got %d", len(serverPublicKey))
	}

	// Perform X25519 ECDH
	shared, err := curve25519.X25519(kp.SecretKey[:], serverPublicKey)
	if err != nil {
		return SessionKeys{}, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// BLAKE2b-512(shared_secret || client_pk || server_pk)
	h, err := blake2b.New512(nil)
	if err != nil {
		return SessionKeys{}, fmt.Errorf("failed to create blake2b hasher: %w", err)
	}
	h.Write(shared)
	h.Write(kp.PublicKey[:])
	h.Write(serverPublicKey)
	digest := h.Sum(nil)

	var keys SessionKeys
	copy(keys.Rx[:], digest[:32])
	copy(keys.Tx[:], digest[32:64])

	return keys, nil
}

// ServerSessionKeys generates server session keys given the server's keypair and the client's public key.
func ServerSessionKeys(kp KeyPair, clientPublicKey []byte) (SessionKeys, error) {
	if len(clientPublicKey) != 32 {
		return SessionKeys{}, fmt.Errorf("client public key must be 32 bytes, got %d", len(clientPublicKey))
	}

	// Perform X25519 ECDH
	shared, err := curve25519.X25519(kp.SecretKey[:], clientPublicKey)
	if err != nil {
		return SessionKeys{}, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// BLAKE2b-512(shared_secret || client_pk || server_pk)
	h, err := blake2b.New512(nil)
	if err != nil {
		return SessionKeys{}, fmt.Errorf("failed to create blake2b hasher: %w", err)
	}
	h.Write(shared)
	h.Write(clientPublicKey)
	h.Write(kp.PublicKey[:])
	digest := h.Sum(nil)

	// Server swaps Rx and Tx compared to client
	var keys SessionKeys
	copy(keys.Rx[:], digest[32:64])
	copy(keys.Tx[:], digest[:32])

	return keys, nil
}

// EncryptRaw encrypts plaintext using the given session key with XChaCha20-Poly1305.
func EncryptRaw(plaintext string, txKey [32]byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(txKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	// Generate a random 24-byte nonce
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), nil)
	return append(ciphertext, nonce...), nil
}

// DecryptRaw decrypts the combined ciphertext and nonce using the given key.
func DecryptRaw(combinedCt []byte, rxKey [32]byte) ([]byte, error) {
	nonceSize := chacha20poly1305.NonceSizeX

	if len(combinedCt) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce from the end of the combined data
	nonceStartIndex := len(combinedCt) - nonceSize
	nonce := combinedCt[nonceStartIndex:]
	ciphertext := combinedCt[:nonceStartIndex]

	aead, err := chacha20poly1305.NewX(rxKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	// Decrypt the ciphertext
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("Failed to decrypt: %v", err)
		return nil, err
	}

	return plaintext, nil
}

// EncryptB64 encrypts the plaintext using the given key and returns a base64 encoded string.
func EncryptB64(plaintext string, key [32]byte) (string, error) {
	rawCt, err := EncryptRaw(plaintext, key)
	if err != nil {
		log.Printf("Failed to encrypt to base64: %v\n", err)
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(rawCt)
	return encoded, nil
}

// DecryptB64 decrypts a base64 encoded ciphertext using the given key and returns the original plaintext.
func DecryptB64(b64Ct string, key [32]byte) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(b64Ct)
	if err != nil {
		log.Printf("Failed to decode base64 ciphertext: %v\n", err)
		return "", err
	}
	plaintextBytes, err := DecryptRaw(ct, key)
	if err != nil {
		log.Printf("Failed to decrypt base64 ciphertext: %v\n", err)
		return "", err
	}
	plaintext := string(plaintextBytes)
	return plaintext, nil
}

// EncryptAsymmetric takes plaintext and a recipient's public key in hex, encrypts the plaintext, and returns a formatted ciphertext.
func EncryptAsymmetric(plaintext, publicKeyHex string) (string, error) {
	recipientPubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		log.Printf("Failed to decode public key hex: %v\n", err)
		return "", err
	}

	// Spin up ephemeral X25519 keys
	kp, err := RandomKeyPair()
	if err != nil {
		return "", err
	}

	// Perform a DHKA
	sessionKeys, err := ClientSessionKeys(kp, recipientPubKeyBytes)
	if err != nil {
		return "", err
	}

	// Encrypt data with XChaCha20-Poly1305
	ciphertext, err := EncryptB64(plaintext, sessionKeys.Tx)
	if err != nil {
		return "", err
	}

	result := fmt.Sprintf("ph:v1:%s:%s", hex.EncodeToString(kp.PublicKey[:]), ciphertext)
	return result, nil
}

// DecryptAsymmetric decrypts a ciphertext string using the provided private and public keys.
func DecryptAsymmetric(ciphertextString, privateKeyHex, publicKeyHex string) (string, error) {
	segments := strings.Split(ciphertextString, ":")

	version := segments[1]
	if version != "v1" {
		err := fmt.Errorf("unsupported version: %s", version)
		log.Println(err)
		return "", err
	}

	ephemeralPublicKeyBytes, err := hex.DecodeString(segments[2])
	if err != nil {
		log.Printf("Failed to decode ephemeral public key hex: %v\n", err)
		return "", err
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		log.Printf("Failed to decode private key hex: %v\n", err)
		return "", err
	}

	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		log.Printf("Failed to decode public key hex: %v\n", err)
		return "", err
	}

	var kp KeyPair
	copy(kp.PublicKey[:], publicKeyBytes)
	copy(kp.SecretKey[:], privateKeyBytes)

	// Perform DHKA
	sessionKeys, err := ServerSessionKeys(kp, ephemeralPublicKeyBytes)
	if err != nil {
		return "", err
	}

	// Extract ciphertext from ph.
	ciphertextB64 := segments[3]

	// Decrypt data with XChaCha20-Poly1305
	plaintext, err := DecryptB64(ciphertextB64, sessionKeys.Rx)
	if err != nil {
		log.Printf("Failed to decrypt asymmetrically: %v\n", err)
		return "", err
	}
	return plaintext, nil
}

// DecryptSecret decrypts a secret's key, value, and optional comment using asymmetric decryption.
func DecryptSecret(secret map[string]interface{}, privateKeyHex, publicKeyHex string) (decryptedKey string, decryptedValue string, decryptedComment string, err error) {
	// Decrypt the key
	key, ok := secret["key"].(string)
	if !ok {
		err = fmt.Errorf("key is not a string")
		return
	}
	decryptedKey, err = DecryptAsymmetric(key, privateKeyHex, publicKeyHex)
	if err != nil {
		log.Printf("Failed to decrypt key: %v\n", err)
		return
	}

	// Decrypt the value
	value, ok := secret["value"].(string)
	if !ok {
		err = fmt.Errorf("value is not a string")
		return
	}
	decryptedValue, err = DecryptAsymmetric(value, privateKeyHex, publicKeyHex)
	if err != nil {
		log.Printf("Failed to decrypt value: %v\n", err)
		return
	}

	// Decrypt the comment if it exists
	comment, ok := secret["comment"].(string)
	if ok && comment != "" {
		decryptedComment, err = DecryptAsymmetric(comment, privateKeyHex, publicKeyHex)
		if err != nil {
			log.Printf("Failed to decrypt comment: %v\n", err)
			err = nil
		}
	}

	return decryptedKey, decryptedValue, decryptedComment, nil
}

// DecryptWrappedKeyShare decrypts the provided ciphertext using the Phase encryption mechanism.
func DecryptWrappedKeyShare(Keyshare1 string, Keyshare0 string, TokenType string, AppToken string, Keyshare1UnwrapKey string, PssUserPublicKey string, Host string) (string, error) {
	// Fetch the wrapped key share using the app token and host
	wrappedKeyShare, err := network.FetchAppKey(TokenType, AppToken, Host)
	if err != nil {
		log.Fatalf("Failed to fetch wrapped key share: %v", err)
		return "", err
	}

	// Decode the wrapped key share from hex
	wrappedKeyShareBytes, err := hex.DecodeString(wrappedKeyShare)
	if err != nil {
		log.Fatalf("Failed to decode wrapped key share from hex: %v", err)
		return "", err
	}

	// Decode Keyshare1UnwrapKey from hex, ensuring it's correctly sized
	keyshare1UnwrapKeyBytes, err := hex.DecodeString(Keyshare1UnwrapKey)
	if err != nil {
		log.Fatalf("Failed to decode Keyshare1UnwrapKey from hex: %v", err)
		return "", err
	}
	if len(keyshare1UnwrapKeyBytes) != 32 {
		log.Fatalf("Incorrect Keyshare1UnwrapKey size: expected 32 bytes, got %d", len(keyshare1UnwrapKeyBytes))
		return "", fmt.Errorf("incorrect Keyshare1UnwrapKey size: expected 32 bytes, got %d", len(keyshare1UnwrapKeyBytes))
	}

	var unwrapKey [32]byte
	copy(unwrapKey[:], keyshare1UnwrapKeyBytes)

	keyshare1, err := DecryptRaw(wrappedKeyShareBytes, unwrapKey)
	if err != nil {
		log.Fatalf("Failed to decrypt wrapped key share: %v", err)
		return "", err
	}

	// Reconstruct the application's private key
	appPrivateKey, err := ReconstructSecret(Keyshare0, string(keyshare1))
	if err != nil {
		log.Fatalf("Failed to reconstruct application's private key: %v", err)
		return "", err
	}

	// Decrypt the ciphertext using the application's private key
	plaintext, err := DecryptAsymmetric(Keyshare1, appPrivateKey, PssUserPublicKey)
	if err != nil {
		log.Fatalf("Failed to decrypt ciphertext: %v", err)
		return "", err
	}

	return plaintext, nil
}

// GenerateEnvKeyPair for X25519 key pair from a hex-encoded seed.
func GenerateEnvKeyPair(seed string) (publicKeyHex, privateKeyHex string, err error) {
	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		return "", "", err
	}
	if len(seedBytes) != 32 {
		return "", "", fmt.Errorf("incorrect seed length: expected 32 bytes, got %d", len(seedBytes))
	}

	h, err := blake2b.New(32, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create blake2b hasher: %w", err)
	}
	h.Write(seedBytes)
	secret := h.Sum(nil)

	// Derive public key from secret key
	var secretArr, public [32]byte
	copy(secretArr[:], secret)
	curve25519.ScalarBaseMult(&public, &secretArr)

	publicKeyHex = hex.EncodeToString(public[:])
	privateKeyHex = hex.EncodeToString(secretArr[:])

	return publicKeyHex, privateKeyHex, nil
}

// Blake2bDigest generates a BLAKE2b-256 hash of the input string with an optional key (salt).
func Blake2bDigest(inputStr, salt string) (string, error) {
	var h [32]byte

	if len(salt) > 0 {
		// Use keyed BLAKE2b
		hasher, err := blake2b.New256([]byte(salt))
		if err != nil {
			log.Printf("Failed to create keyed BLAKE2b hasher: %v\n", err)
			return "", err
		}
		hasher.Write([]byte(inputStr))
		sum := hasher.Sum(nil)
		copy(h[:], sum)
	} else {
		// Use unkeyed BLAKE2b
		h = blake2b.Sum256([]byte(inputStr))
	}

	return hex.EncodeToString(h[:]), nil
}

// Assemble the shares together into a secret XORBytes
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("byte slices a and b must have the same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

// ReconstructSecret reconstructs the secret from two hex-encoded shares.
func ReconstructSecret(share1, share2 string) (string, error) {
	// Decode the hex-encoded shares to bytes.
	bytesShare1, err := hex.DecodeString(share1)
	if err != nil {
		return "", fmt.Errorf("failed to decode share1: %w", err)
	}
	bytesShare2, err := hex.DecodeString(share2)
	if err != nil {
		return "", fmt.Errorf("failed to decode share2: %w", err)
	}

	// XOR the byte slices to reconstruct the secret.
	reconstructedSecret, err := XORBytes(bytesShare1, bytesShare2)
	if err != nil {
		return "", fmt.Errorf("failed to XOR shares: %w", err)
	}

	// Encode the reconstructed secret back to a hex string.
	return hex.EncodeToString(reconstructedSecret), nil
}
