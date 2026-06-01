package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func EncryptFixedCTR(plaintextStr string, key []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("key must be 16, 24, or 32 bytes long instead of %d", len(key))
	}

	plaintext := []byte(plaintextStr)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	fixedIV := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, fixedIV)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
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
	encrypted, err := EncryptFixedCTR(text, myKey)
	if err != nil {
		fmt.Printf("Error encrypting: %v\n", err)
		return
	}

	fmt.Printf("Encrypted: %s\n", encrypted)
}
