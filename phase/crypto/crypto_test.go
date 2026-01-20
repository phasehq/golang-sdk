package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

// =============================================================================
// XORBytes Tests
// =============================================================================

func TestXORBytes(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "basic XOR",
			a:        []byte{0x00, 0xFF, 0xAA, 0x55},
			b:        []byte{0xFF, 0xFF, 0x55, 0xAA},
			expected: []byte{0xFF, 0x00, 0xFF, 0xFF},
			wantErr:  false,
		},
		{
			name:     "XOR with zeros",
			a:        []byte{0x12, 0x34, 0x56, 0x78},
			b:        []byte{0x00, 0x00, 0x00, 0x00},
			expected: []byte{0x12, 0x34, 0x56, 0x78},
			wantErr:  false,
		},
		{
			name:     "XOR with self gives zeros",
			a:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
			b:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expected: []byte{0x00, 0x00, 0x00, 0x00},
			wantErr:  false,
		},
		{
			name:    "length mismatch",
			a:       []byte{0x00, 0xFF},
			b:       []byte{0xFF},
			wantErr: true,
		},
		{
			name:     "empty slices",
			a:        []byte{},
			b:        []byte{},
			expected: []byte{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := XORBytes(tt.a, tt.b)
			if tt.wantErr {
				if err == nil {
					t.Errorf("XORBytes() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("XORBytes() unexpected error: %v", err)
				return
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("XORBytes() = %x, want %x", result, tt.expected)
			}
		})
	}
}

func TestXORBytesReversibility(t *testing.T) {
	// XOR is reversible: (a XOR b) XOR b = a
	a := make([]byte, 32)
	b := make([]byte, 32)
	rand.Read(a)
	rand.Read(b)

	xored, err := XORBytes(a, b)
	if err != nil {
		t.Fatalf("XORBytes() error: %v", err)
	}

	recovered, err := XORBytes(xored, b)
	if err != nil {
		t.Fatalf("XORBytes() error: %v", err)
	}

	if !bytes.Equal(recovered, a) {
		t.Errorf("XOR reversibility failed: got %x, want %x", recovered, a)
	}
}

// =============================================================================
// ReconstructSecret Tests
// =============================================================================

func TestReconstructSecret(t *testing.T) {
	tests := []struct {
		name     string
		share1   string
		share2   string
		expected string
		wantErr  bool
	}{
		{
			name:     "basic reconstruction",
			share1:   "deadbeef",
			share2:   "cafebabe",
			expected: "14530451", // 0xdeadbeef XOR 0xcafebabe
			wantErr:  false,
		},
		{
			name:    "invalid hex share1",
			share1:  "xyz",
			share2:  "cafe",
			wantErr: true,
		},
		{
			name:    "invalid hex share2",
			share1:  "cafe",
			share2:  "xyz",
			wantErr: true,
		},
		{
			name:    "length mismatch",
			share1:  "deadbeef",
			share2:  "cafe",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ReconstructSecret(tt.share1, tt.share2)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ReconstructSecret() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("ReconstructSecret() unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("ReconstructSecret() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Blake2bDigest Tests
// =============================================================================

func TestBlake2bDigest(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		salt     string
		expected string // pre-computed expected hash
	}{
		{
			name:     "empty input no salt",
			input:    "",
			salt:     "",
			expected: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		},
		{
			name:  "hello world no salt",
			input: "hello world",
			salt:  "",
			// BLAKE2b-256 of "hello world"
			expected: "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Blake2bDigest(tt.input, tt.salt)
			if err != nil {
				t.Errorf("Blake2bDigest() error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Blake2bDigest() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestBlake2bDigestWithSalt(t *testing.T) {
	// Test that salt changes the output
	input := "test data"
	hash1, _ := Blake2bDigest(input, "")
	hash2, _ := Blake2bDigest(input, "salt1")
	hash3, _ := Blake2bDigest(input, "salt2")

	if hash1 == hash2 {
		t.Error("Salt should change hash output")
	}
	if hash2 == hash3 {
		t.Error("Different salts should produce different hashes")
	}
}

func TestBlake2bDigestDeterminism(t *testing.T) {
	// Same input should always produce same output
	input := "deterministic test"
	salt := "my-salt"

	hash1, _ := Blake2bDigest(input, salt)
	hash2, _ := Blake2bDigest(input, salt)

	if hash1 != hash2 {
		t.Errorf("Blake2bDigest not deterministic: %s != %s", hash1, hash2)
	}
}

// =============================================================================
// KeyPair Generation Tests
// =============================================================================

func TestRandomKeyPair(t *testing.T) {
	kp1, err := RandomKeyPair()
	if err != nil {
		t.Fatalf("RandomKeyPair() error: %v", err)
	}

	// Keys should not be all zeros
	var zeroKey [32]byte
	if kp1.PublicKey == zeroKey {
		t.Error("Public key should not be all zeros")
	}
	if kp1.SecretKey == zeroKey {
		t.Error("Secret key should not be all zeros")
	}

	// Generate another keypair - should be different
	kp2, err := RandomKeyPair()
	if err != nil {
		t.Fatalf("RandomKeyPair() error: %v", err)
	}

	if kp1.PublicKey == kp2.PublicKey {
		t.Error("Random keypairs should have different public keys")
	}
	if kp1.SecretKey == kp2.SecretKey {
		t.Error("Random keypairs should have different secret keys")
	}
}

func TestRandomKeyPairValidity(t *testing.T) {
	// Verify that public key is correctly derived from secret key
	kp, err := RandomKeyPair()
	if err != nil {
		t.Fatalf("RandomKeyPair() error: %v", err)
	}

	// Re-derive public key from secret key
	var derivedPublic [32]byte
	curve25519.ScalarBaseMult(&derivedPublic, &kp.SecretKey)

	if derivedPublic != kp.PublicKey {
		t.Error("Public key not correctly derived from secret key")
	}
}

func TestGenerateEnvKeyPair(t *testing.T) {
	// Test deterministic key generation from seed
	seed := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	pub1, priv1, err := GenerateEnvKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateEnvKeyPair() error: %v", err)
	}

	pub2, priv2, err := GenerateEnvKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateEnvKeyPair() error: %v", err)
	}

	// Same seed should produce same keys
	if pub1 != pub2 {
		t.Error("Same seed should produce same public key")
	}
	if priv1 != priv2 {
		t.Error("Same seed should produce same private key")
	}

	// Different seed should produce different keys
	seed2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	pub3, priv3, err := GenerateEnvKeyPair(seed2)
	if err != nil {
		t.Fatalf("GenerateEnvKeyPair() error: %v", err)
	}

	if pub1 == pub3 {
		t.Error("Different seeds should produce different public keys")
	}
	if priv1 == priv3 {
		t.Error("Different seeds should produce different private keys")
	}
}

func TestGenerateEnvKeyPairInvalidSeed(t *testing.T) {
	// Invalid hex
	_, _, err := GenerateEnvKeyPair("xyz")
	if err == nil {
		t.Error("Expected error for invalid hex seed")
	}

	// Wrong length
	_, _, err = GenerateEnvKeyPair("0123456789abcdef")
	if err == nil {
		t.Error("Expected error for wrong length seed")
	}
}

func TestGenerateEnvKeyPairMatchesBlake2b(t *testing.T) {
	// Verify that GenerateEnvKeyPair correctly hashes the seed
	// This tests the libsodium compatibility fix
	seed := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	seedBytes, _ := hex.DecodeString(seed)

	// Hash the seed with BLAKE2b-256 (what libsodium does)
	h, _ := blake2b.New(32, nil)
	h.Write(seedBytes)
	expectedSecret := h.Sum(nil)

	// Derive public key
	var expectedSecretArr, expectedPublic [32]byte
	copy(expectedSecretArr[:], expectedSecret)
	curve25519.ScalarBaseMult(&expectedPublic, &expectedSecretArr)

	// Get from our function
	pubHex, privHex, _ := GenerateEnvKeyPair(seed)
	pubBytes, _ := hex.DecodeString(pubHex)
	privBytes, _ := hex.DecodeString(privHex)

	if !bytes.Equal(privBytes, expectedSecret) {
		t.Error("GenerateEnvKeyPair private key doesn't match expected BLAKE2b hash of seed")
	}
	if !bytes.Equal(pubBytes, expectedPublic[:]) {
		t.Error("GenerateEnvKeyPair public key doesn't match expected derivation")
	}
}

// =============================================================================
// Session Key Tests
// =============================================================================

func TestSessionKeySymmetry(t *testing.T) {
	// The core test: client's Tx should equal server's Rx
	// This ensures encrypted data can be decrypted

	clientKP, _ := RandomKeyPair()
	serverKP, _ := RandomKeyPair()

	clientKeys, err := ClientSessionKeys(clientKP, serverKP.PublicKey[:])
	if err != nil {
		t.Fatalf("ClientSessionKeys() error: %v", err)
	}

	serverKeys, err := ServerSessionKeys(serverKP, clientKP.PublicKey[:])
	if err != nil {
		t.Fatalf("ServerSessionKeys() error: %v", err)
	}

	// Client's Tx should equal Server's Rx
	if clientKeys.Tx != serverKeys.Rx {
		t.Error("Client Tx != Server Rx - encryption/decryption will fail")
	}

	// Client's Rx should equal Server's Tx
	if clientKeys.Rx != serverKeys.Tx {
		t.Error("Client Rx != Server Tx - encryption/decryption will fail")
	}
}

func TestSessionKeyDeterminism(t *testing.T) {
	// Same inputs should produce same outputs
	clientKP, _ := RandomKeyPair()
	serverKP, _ := RandomKeyPair()

	keys1, _ := ClientSessionKeys(clientKP, serverKP.PublicKey[:])
	keys2, _ := ClientSessionKeys(clientKP, serverKP.PublicKey[:])

	if keys1.Tx != keys2.Tx || keys1.Rx != keys2.Rx {
		t.Error("ClientSessionKeys not deterministic")
	}
}

func TestSessionKeyInvalidInput(t *testing.T) {
	kp, _ := RandomKeyPair()

	// Wrong length public key
	_, err := ClientSessionKeys(kp, []byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("Expected error for invalid public key length")
	}

	_, err = ServerSessionKeys(kp, []byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("Expected error for invalid public key length")
	}
}

// =============================================================================
// Encryption/Decryption Tests
// =============================================================================

func TestEncryptDecryptRawRoundTrip(t *testing.T) {
	key := [32]byte{}
	rand.Read(key[:])

	testCases := []string{
		"",
		"hello",
		"hello world",
		"The quick brown fox jumps over the lazy dog",
		strings.Repeat("a", 1000),
		strings.Repeat("🔐", 100), // Unicode
	}

	for _, plaintext := range testCases {
		t.Run(plaintext[:min(len(plaintext), 20)], func(t *testing.T) {
			ciphertext, err := EncryptRaw(plaintext, key)
			if err != nil {
				t.Fatalf("EncryptRaw() error: %v", err)
			}

			decrypted, err := DecryptRaw(ciphertext, key)
			if err != nil {
				t.Fatalf("DecryptRaw() error: %v", err)
			}

			if string(decrypted) != plaintext {
				t.Errorf("Round-trip failed: got %q, want %q", string(decrypted), plaintext)
			}
		})
	}
}

func TestEncryptDecryptB64RoundTrip(t *testing.T) {
	key := [32]byte{}
	rand.Read(key[:])

	plaintext := "secret message for base64 encoding"

	ciphertext, err := EncryptB64(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptB64() error: %v", err)
	}

	decrypted, err := DecryptB64(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptB64() error: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := [32]byte{}
	key2 := [32]byte{}
	rand.Read(key1[:])
	rand.Read(key2[:])

	plaintext := "secret message"
	ciphertext, _ := EncryptRaw(plaintext, key1)

	// Decrypting with wrong key should fail
	_, err := DecryptRaw(ciphertext, key2)
	if err == nil {
		t.Error("Expected error when decrypting with wrong key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := [32]byte{}
	rand.Read(key[:])

	plaintext := "secret message"
	ciphertext, _ := EncryptRaw(plaintext, key)

	// Tamper with the ciphertext (not the nonce at the end)
	if len(ciphertext) > 30 {
		ciphertext[5] ^= 0xFF
	}

	// Should fail authentication
	_, err := DecryptRaw(ciphertext, key)
	if err == nil {
		t.Error("Expected error when decrypting tampered ciphertext")
	}
}

func TestEncryptProducesUniqueCiphertext(t *testing.T) {
	key := [32]byte{}
	rand.Read(key[:])

	plaintext := "same message"

	ct1, _ := EncryptRaw(plaintext, key)
	ct2, _ := EncryptRaw(plaintext, key)

	// Same plaintext should produce different ciphertext (due to random nonce)
	if bytes.Equal(ct1, ct2) {
		t.Error("Same plaintext should produce different ciphertext due to random nonce")
	}
}

func TestCiphertextFormat(t *testing.T) {
	key := [32]byte{}
	rand.Read(key[:])

	plaintext := "test"
	ciphertext, _ := EncryptRaw(plaintext, key)

	// Ciphertext should be: encrypted_data (len(plaintext) + 16 tag) + nonce (24)
	expectedLen := len(plaintext) + 16 + 24
	if len(ciphertext) != expectedLen {
		t.Errorf("Ciphertext length = %d, want %d", len(ciphertext), expectedLen)
	}
}

// =============================================================================
// Asymmetric Encryption Tests
// =============================================================================

func TestEncryptDecryptAsymmetricRoundTrip(t *testing.T) {
	// Generate recipient keypair
	recipientKP, _ := RandomKeyPair()
	recipientPubHex := hex.EncodeToString(recipientKP.PublicKey[:])
	recipientPrivHex := hex.EncodeToString(recipientKP.SecretKey[:])

	testCases := []string{
		"short",
		"medium length secret message",
		strings.Repeat("long", 250),
		"unicode: 日本語 🔐 émoji",
	}

	for _, plaintext := range testCases {
		t.Run(plaintext[:min(len(plaintext), 20)], func(t *testing.T) {
			ciphertext, err := EncryptAsymmetric(plaintext, recipientPubHex)
			if err != nil {
				t.Fatalf("EncryptAsymmetric() error: %v", err)
			}

			// Verify format: ph:v1:ephemeral_pubkey:base64_ciphertext
			parts := strings.Split(ciphertext, ":")
			if len(parts) != 4 {
				t.Fatalf("Invalid ciphertext format: expected 4 parts, got %d", len(parts))
			}
			if parts[0] != "ph" {
				t.Errorf("Prefix = %s, want 'ph'", parts[0])
			}
			if parts[1] != "v1" {
				t.Errorf("Version = %s, want 'v1'", parts[1])
			}

			decrypted, err := DecryptAsymmetric(ciphertext, recipientPrivHex, recipientPubHex)
			if err != nil {
				t.Fatalf("DecryptAsymmetric() error: %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("Round-trip failed: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestDecryptAsymmetricWithWrongKey(t *testing.T) {
	recipientKP, _ := RandomKeyPair()
	wrongKP, _ := RandomKeyPair()

	recipientPubHex := hex.EncodeToString(recipientKP.PublicKey[:])
	wrongPrivHex := hex.EncodeToString(wrongKP.SecretKey[:])
	wrongPubHex := hex.EncodeToString(wrongKP.PublicKey[:])

	ciphertext, _ := EncryptAsymmetric("secret", recipientPubHex)

	// Try to decrypt with wrong keypair
	_, err := DecryptAsymmetric(ciphertext, wrongPrivHex, wrongPubHex)
	if err == nil {
		t.Error("Expected error when decrypting with wrong key")
	}
}

func TestAsymmetricCiphertextUniqueness(t *testing.T) {
	recipientKP, _ := RandomKeyPair()
	recipientPubHex := hex.EncodeToString(recipientKP.PublicKey[:])

	ct1, _ := EncryptAsymmetric("same message", recipientPubHex)
	ct2, _ := EncryptAsymmetric("same message", recipientPubHex)

	// Each encryption uses a new ephemeral keypair + random nonce
	if ct1 == ct2 {
		t.Error("Same plaintext should produce different ciphertext")
	}

	// But both should decrypt to the same plaintext
	recipientPrivHex := hex.EncodeToString(recipientKP.SecretKey[:])
	pt1, _ := DecryptAsymmetric(ct1, recipientPrivHex, recipientPubHex)
	pt2, _ := DecryptAsymmetric(ct2, recipientPrivHex, recipientPubHex)

	if pt1 != pt2 {
		t.Error("Both ciphertexts should decrypt to same plaintext")
	}
}

// =============================================================================
// Known Answer Tests (KATs) - Compatibility Verification
// =============================================================================

func TestBlake2b256KnownAnswers(t *testing.T) {
	// These are standard BLAKE2b-256 test vectors
	tests := []struct {
		input    string
		expected string
	}{
		{"", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
		{"abc", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
	}

	for _, tt := range tests {
		h := blake2b.Sum256([]byte(tt.input))
		result := hex.EncodeToString(h[:])
		if result != tt.expected {
			t.Errorf("BLAKE2b-256(%q) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

// =============================================================================
// Security Tests
// =============================================================================

func TestNonceIsRandom(t *testing.T) {
	key := [32]byte{}
	rand.Read(key[:])

	nonces := make(map[string]bool)

	for i := 0; i < 100; i++ {
		ct, _ := EncryptRaw("test", key)
		// Extract nonce (last 24 bytes)
		nonce := ct[len(ct)-24:]
		nonceHex := hex.EncodeToString(nonce)

		if nonces[nonceHex] {
			t.Error("Nonce collision detected - random number generator issue")
		}
		nonces[nonceHex] = true
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkEncryptRaw(b *testing.B) {
	key := [32]byte{}
	rand.Read(key[:])
	plaintext := strings.Repeat("a", 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptRaw(plaintext, key)
	}
}

func BenchmarkDecryptRaw(b *testing.B) {
	key := [32]byte{}
	rand.Read(key[:])
	plaintext := strings.Repeat("a", 1024)
	ciphertext, _ := EncryptRaw(plaintext, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptRaw(ciphertext, key)
	}
}

func BenchmarkBlake2bDigest(b *testing.B) {
	input := strings.Repeat("a", 1024)
	salt := "benchmark-salt"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Blake2bDigest(input, salt)
	}
}

func BenchmarkSessionKeys(b *testing.B) {
	clientKP, _ := RandomKeyPair()
	serverKP, _ := RandomKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClientSessionKeys(clientKP, serverKP.PublicKey[:])
	}
}

func BenchmarkEncryptAsymmetric(b *testing.B) {
	recipientKP, _ := RandomKeyPair()
	recipientPubHex := hex.EncodeToString(recipientKP.PublicKey[:])
	plaintext := "benchmark secret message"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptAsymmetric(plaintext, recipientPubHex)
	}
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
