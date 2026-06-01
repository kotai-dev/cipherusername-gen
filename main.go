package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

func EncryptAESCTR(plaintextStr string, key []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("key must be 16, 24, or 32 bytes long instead of %d", len(key))
	}

	plaintext := []byte(plaintextStr)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext, nonce)

	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func DecryptAESCTR(ciphertextStr string, key []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("key must be 16, 24, or 32 bytes long instead of %d", len(key))
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(ciphertextStr)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	nonce := ciphertext[:aes.BlockSize]
	realCiphertext := ciphertext[aes.BlockSize:]

	stream := cipher.NewCTR(block, nonce)
	plaintext := make([]byte, len(realCiphertext))
	stream.XORKeyStream(plaintext, realCiphertext)

	return string(plaintext), nil
}

func main() {
	// read encryption key from environment variable
	envKey := os.Getenv("ENCRYPTION_KEY")
	if envKey == "" {
		fmt.Println("ENCRYPTION_KEY environment variable is not set")
		return
	}
	myKey := []byte(envKey)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter username to encrypt: ") // plaintext

	text, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return
	}

	// Remove newline character
	text = strings.TrimSpace(text)
	if text == "" {
		fmt.Println("No input provided")
		return
	}

	// Encrypt
	encrypted, err := EncryptAESCTR(text, myKey)
	if err != nil {
		fmt.Printf("Error encrypting: %v\n", err)
		return
	}

	fmt.Printf("Encrypted: %s\n", encrypted)
}
