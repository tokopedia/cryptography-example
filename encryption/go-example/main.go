package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mathRand "math/rand"
)

func Encrypt(pubKey *rsa.PublicKey, message []byte) ([]byte, string, error) {
	// Create random key
	key := randomString(32)

	// Encrypt payload with random key
	encrypted, err := encrypt(message, []byte(key))
	if err != nil {
		return nil, "", errors.New("failed to encrypt payload")
	}

	// Decrypt random key that have been used for payload encryption
	hash := sha256.New()
	encKey, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, []byte(key), nil)
	if err != nil {
		return nil, "", errors.New("failed to encrypt encryption key")
	}

	// Encode encrypted key to base 64
	encodedKey := base64.StdEncoding.EncodeToString(encKey)

	// Return encrypted payload and key
	return encrypted, encodedKey, nil
}

func Decrypt(privKey *rsa.PrivateKey, message []byte, encryptedKey string) ([]byte, error) {
	// Decode key from base64
	decodedKey, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, errors.New("failed to decode payload")
	}

	// Decrypt encrypted random generated key
	hash := sha256.New()
	decryptedKey, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, decodedKey, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt encryption key")
	}

	// Decrypt payload using decrypted key
	decrypted, err := decrypt(message, decryptedKey)
	if err != nil {
		return nil, errors.New("failed to decrypt payload")
	}

	// Return decrypted payload
	return decrypted, nil
}

func main() {
	// Read private key
	privKeyStr, err := ioutil.ReadFile("../key/priv.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Parse private key
	privKey, err := ParseRsaPrivateKeyFromPemStr(string(privKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	// Read public key
	pubKeyStr, err := ioutil.ReadFile("../key/pub.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Parse public key
	pubKey, err := ParseRsaPublicKeyFromPemStr(string(pubKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	// Payload
	payload := `{"name":"john-doe", "method":"hello-world", "value":"lorem-ipsum"}`

	// Encryption
	encPayload, encKey, err := Encrypt(pubKey, []byte(payload))
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Encrypted Payload: ", string(encPayload))
	log.Println("Encrypted Key: ", encKey)

	// Decryption
	decPayload, err := Decrypt(privKey, encPayload, encKey)

	log.Println("Decrypted Payload: ", string(decPayload))
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse pem block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse pem block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break
	}

	return nil, errors.New("key type is not RSA")
}

func encrypt(message, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, message, nil)
	ciphertext = append(ciphertext, nonce...)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	return []byte(encoded), nil
}

func decrypt(encrypted, key []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(encrypted))
	if err != nil {
		return nil, err
	}

	if len(decoded) < 12 {
		return nil, errors.New("insufficient payload length")
	}

	nonce := decoded[len(decoded)-12:]
	decoded = decoded[:len(decoded)-12]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plain, err := aesGCM.Open(nil, nonce, decoded, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypt, %s", err)
	}

	return plain, nil
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[mathRand.Intn(len(letters))]
	}

	return string(b)
}
