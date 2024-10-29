package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/jamesruan/sodium"
	"github.com/phasehq/golang-sdk/phase/network"
)

// Spin up an ephemeral X25519 keypair
func RandomKeyPair() (sodium.KXKP, error) {
	kp := sodium.MakeKXKP()
	return kp, nil
}

// ClientSessionKeys generates client session keys given a client's ephemeral keypair and the recipient's public key.
func ClientSessionKeys(kp sodium.KXKP, recipientPublicKey []byte) (*sodium.KXSessionKeys, error) {
	recipientPubKey := sodium.KXPublicKey{Bytes: recipientPublicKey}
	sessionKeys, err := kp.ClientSessionKeys(recipientPubKey)
	if err != nil {
		log.Printf("Failed to generate client session keys: %v\n", err)
		return nil, err
	}
	return sessionKeys, nil
}

// ServerSessionKeys generates server session keys given the server's keypair and the client's public key.
func ServerSessionKeys(kp sodium.KXKP, clientPublicKey []byte) (*sodium.KXSessionKeys, error) {
	clientPubKey := sodium.KXPublicKey{Bytes: clientPublicKey}
	sessionKeys, err := kp.ServerSessionKeys(clientPubKey)
	if err != nil {
		log.Printf("Failed to generate server session keys: %v\n", err)
		return nil, err
	}
	return sessionKeys, nil
}

// EncryptRaw encrypts plaintext using the given session key with XChaCha20Poly1305.
func EncryptRaw(plaintext string, txKey sodium.KXSessionKey) ([]byte, error) {
	// Convert txKey to a suitable format for XChaCha20Poly1305 encryption.
	aeadKey := sodium.AEADXCPKey{Bytes: txKey.Bytes}

	// Generate a 192 bit random nonce for XChaCha20Poly1305.
	var nonce sodium.AEADXCPNonce
	sodium.Randomize(&nonce)

	// Convert plaintext to sodium.Bytes for encryption.
	plaintextBytes := sodium.Bytes(plaintext)

	// Encrypt the plaintext using XChaCha20Poly1305 with the derived key and nonce.
	ciphertext := plaintextBytes.AEADXCPEncrypt(sodium.Bytes(nil), nonce, aeadKey)

	// Append the nonce to the ciphertext.
	return append(ciphertext, nonce.Bytes...), nil
}

// DecryptRaw decrypts the combined nonce and ciphertext using the given key.
func DecryptRaw(combinedCt []byte, rxKey sodium.KXSessionKey) ([]byte, error) {
	nonceSize := sodium.AEADXCPNonce{}.Size()

	// Extract the nonce from the end of the combined data.
	nonceStartIndex := len(combinedCt) - nonceSize
	nonceBytes := combinedCt[nonceStartIndex:]
	ciphertext := combinedCt[:nonceStartIndex]

	// Convert the session key to the format expected for decryption.
	aeadKey := sodium.AEADXCPKey{Bytes: rxKey.Bytes}

	// Initialize the nonce with the extracted bytes.
	var nonce sodium.AEADXCPNonce
	if len(nonce.Bytes) < nonceSize {
		nonce.Bytes = make([]byte, nonceSize)
	}
	copy(nonce.Bytes, nonceBytes)

	// Decrypt the ciphertext using XChaCha20Poly1305 with the derived key and extracted nonce.
	plaintextBytes, err := sodium.Bytes(ciphertext).AEADXCPDecrypt(sodium.Bytes(nil), nonce, aeadKey)
	if err != nil {
		log.Printf("Failed to decrypt: %v", err)
		return nil, err
	}

	return plaintextBytes, nil
}

// EncryptB64 encrypts the plaintext using the given key and returns a base64 encoded string.
func EncryptB64(plaintext string, key sodium.KXSessionKey) (string, error) {
	rawCt, err := EncryptRaw(plaintext, key)
	if err != nil {
		log.Printf("Failed to encrypt to base64: %v\n", err)
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(rawCt)
	return encoded, nil
}

// DecryptB64 decrypts a base64 encoded ciphertext using the given key and returns the original plaintext.
func DecryptB64(b64Ct string, key sodium.KXSessionKey) (string, error) {
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

	// Encrypt data with XChaCha20-poly1305
	ciphertext, err := EncryptB64(plaintext, sessionKeys.Tx)
	if err != nil {
		return "", err
	}

	result := fmt.Sprintf("ph:v1:%s:%s", hex.EncodeToString(kp.PublicKey.Bytes), ciphertext)
	return result, nil
}

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

	kp := sodium.KXKP{
		PublicKey: sodium.KXPublicKey{Bytes: publicKeyBytes},
		SecretKey: sodium.KXSecretKey{Bytes: privateKeyBytes},
	}

	// Perform DHKA
	sessionKeys, err := ServerSessionKeys(kp, ephemeralPublicKeyBytes)
	if err != nil {
		return "", err
	}

	// Extract ciphertext from ph.
	ciphertextB64 := segments[3]

	// Decrypt data with XChaCha20-poly1305
	plaintext, err := DecryptB64(ciphertextB64, sessionKeys.Rx)
	if err != nil {
		log.Printf("Failed to decrypt asymmetrically: %v\n", err)
		return "", err
	}
	return plaintext, nil
}

// decryptSecret decrypts a secret's key, value, and optional comment using asymmetric decryption.
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

// Decrypt decrypts the provided ciphertext using the Phase encryption mechanism.
func DecryptWrappedKeyShare(Keyshare1 string, Keyshare0 string, TokenType string, AppToken string, Keyshare1UnwrapKey string, PssUserPublicKey string, Host string) (string, error) {
	// Fetch the wrapped key share using the app token and host
	wrappedKeyShare, err := network.FetchAppKey(TokenType, AppToken, Host)
	if err != nil {
		log.Fatalf("Failed to fetch wrapped key share: %v", err)
		return "", err
	}

	// Decode the wrapped key share from hex, not base64
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
	if len(keyshare1UnwrapKeyBytes) != 32 { // Sodium expects a 32-byte key
		log.Fatalf("Incorrect Keyshare1UnwrapKey size: expected 32 bytes, got %d", len(keyshare1UnwrapKeyBytes))
		return "", err
	}

	keyshare1, err := DecryptRaw(wrappedKeyShareBytes, sodium.KXSessionKey{Bytes: keyshare1UnwrapKeyBytes})
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

func GenerateEnvKeyPair(seed string) (publicKeyHex, privateKeyHex string, err error) {
	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		return "", "", err
	}
	if len(seedBytes) != 32 {
		return "", "", fmt.Errorf("incorrect seed length: expected 32 bytes, got %d", len(seedBytes))
	}

	// Prepare the seed as KXSeed
	var seedKX sodium.KXSeed
	copy(seedKX.Bytes[:], seedBytes)

	// Allocate slice if KXSeed.Bytes is a slice
	seedKX.Bytes = make([]byte, len(seedBytes))
	copy(seedKX.Bytes, seedBytes)

	// Generate key pair from seed
	keyPair := sodium.SeedKXKP(seedKX)

	publicKeyHex = hex.EncodeToString(keyPair.PublicKey.Bytes[:])
	privateKeyHex = hex.EncodeToString(keyPair.SecretKey.Bytes[:])

	return publicKeyHex, privateKeyHex, nil
}

// Blake2bDigest generates a BLAKE2b hash of the input string with a salt using the sodium library.
func Blake2bDigest(inputStr, salt string) (string, error) {
	hashSize := 32 // 32 bytes (256 bits) as an example
	var hasher *sodium.GenericHash
	if len(salt) > 0 {
		// Convert the salt string to a GenericHashKey.
		key := sodium.GenericHashKey{Bytes: sodium.Bytes([]byte(salt))}
		hasher = sodium.NewGenericHashKeyed(hashSize, key).(*sodium.GenericHash)
	} else {
		hasher = sodium.NewGenericHash(hashSize).(*sodium.GenericHash)
	}

	// Write the input string to the hasher.
	_, err := hasher.Write([]byte(inputStr))
	if err != nil {
		log.Printf("Failed to write to BLAKE2b hasher: %v\n", err)
		return "", err
	}

	// Compute the hash.
	hashed := hasher.Sum(nil)

	// Encode the hash to a hexadecimal string.
	hexEncoded := hex.EncodeToString(hashed)
	return hexEncoded, nil
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
