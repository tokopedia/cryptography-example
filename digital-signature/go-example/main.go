package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
)

type SignatureTypePSS struct{}
type SignatureTypePKCS struct{}

func (s *SignatureTypePSS) Sign(privKey *rsa.PrivateKey, msg string) (string, error) {
	hashed := sha256.Sum256([]byte(msg))
	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		fmt.Println("error signing", err)
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func (s *SignatureTypePSS) Verify(pubKey *rsa.PublicKey, msg, signature string) error {
	if signature == "" {
		return errors.New("signature is empty")
	}

	message := []byte(msg)
	bSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		log.Println("error decoding", err)
		return err
	}

	hashed := sha256.Sum256(message)
	err = rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], bSignature, nil)
	if err != nil {
		log.Println("error verifying", err)
		return err
	}

	return nil
}

func (s *SignatureTypePKCS) Sign(privKey *rsa.PrivateKey, msg string) (string, error) {
	rng := rand.Reader
	message := []byte(msg)
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rng, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("error signing", err)
		return "", err
	}

	sEnc := base64.StdEncoding.EncodeToString(signature)
	return sEnc, nil
}

func (s *SignatureTypePKCS) Verify(pubKey *rsa.PublicKey, msg string, base64Signature string) error {
	message := []byte(msg)
	bSignature, err := base64.StdEncoding.DecodeString(base64Signature)

	if err != nil {
		fmt.Println("Failed to decode signature")
		return err
	}
	hashed := sha256.Sum256(message)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], bSignature)
	if err != nil {
		fmt.Println("error verifying", err)
		return err
	}

	return nil
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
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func main() {
	params := `{}`
	privKeyStr, err := ioutil.ReadFile("./key/priv.pem")
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := ParseRsaPrivateKeyFromPemStr(string(privKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	pubKeyStr, err := ioutil.ReadFile("./key/pub.pem")
	if err != nil {
		log.Fatal(err)
	}

	pubKey, err := ParseRsaPublicKeyFromPemStr(string(pubKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	signer := SignatureTypePSS{}
	// signer := SignatureTypePKCS{}
	signature, err := signer.Sign(privKey, params)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(signature)

	err = signer.Verify(pubKey, params, signature)
	fmt.Println("isVerified: ", err == nil)
}
