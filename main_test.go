package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestEncryptRoundTrip(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	message := []byte(`{"paste":"private data"}`)

	paste, err := encrypt(masterKey, message)
	if err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}

	iv, err := base64.RawStdEncoding.DecodeString(paste.IV)
	if err != nil {
		t.Fatalf("decode IV: %v", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(paste.Salt)
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	if len(iv) != 12 {
		t.Fatalf("IV length = %d, want 12", len(iv))
	}
	if len(salt) != 8 {
		t.Fatalf("salt length = %d, want 8", len(salt))
	}

	additionalData, err := json.Marshal(paste.adata())
	if err != nil {
		t.Fatalf("marshal additional data: %v", err)
	}
	key := pbkdf2.Key(masterKey, salt, paste.Iterations, paste.KeySize/8, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("create AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("create GCM: %v", err)
	}
	decrypted, err := gcm.Open(nil, iv, paste.Data, additionalData)
	if err != nil {
		t.Fatalf("decrypt ciphertext: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Fatalf("decrypted message = %q, want %q", decrypted, message)
	}

	secondPaste, err := encrypt(masterKey, message)
	if err != nil {
		t.Fatalf("encrypt() second call error = %v", err)
	}
	if paste.IV == secondPaste.IV {
		t.Fatal("encrypt() reused the IV")
	}
}
