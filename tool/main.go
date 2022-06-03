package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/tokopedia/cryptography-example/digital-signature/go-example/lib"
)

type PaddingType string

type signedData struct {
	Payload                    string      `json:"payload"`
	PaddingType                PaddingType `json:"padding_type"`
	PublicKeyFile              string      `json:"public_key"`
	Signature                  string      `json:"signature"`
	IsDigitalSignatureVerified bool        `json:"is_digital_signature_verified"`
}

func main() {
	signedData, err := readConfig()
	if err != nil {
		log.Fatal(err)
	}

	pubKeyStr, err := ioutil.ReadFile(signedData.PublicKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	pubKey, err := lib.ParseRsaPublicKeyFromPemStr(string(pubKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	signer, err := PaddingTypeFactory(signedData.PaddingType)
	if err != nil {
		log.Fatal(err)
	}

	signedData.IsDigitalSignatureVerified = true

	err = signer.Verify(pubKey, signedData.Payload, signedData.Signature)
	if err != nil {
		signedData.IsDigitalSignatureVerified = false
	}

	prettyJson, _ := json.MarshalIndent(signedData, "", "  ")
	fmt.Printf("%s\n", prettyJson)

	// write to file
	_ = ioutil.WriteFile("result.json", prettyJson, 0644)
}

func readConfig() (*signedData, error) {
	file, err := os.Open("digital_signature.json")
	defer file.Close()
	if err != nil {
		return nil, err
	}

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var signedData signedData
	err = json.Unmarshal(byteValue, &signedData)
	if err != nil {
		return nil, err
	}

	return &signedData, nil
}

type SignerItf interface {
	Sign(privKey *rsa.PrivateKey, msg string) (string, error)
	Verify(pubKey *rsa.PublicKey, msg, signature string) error
}

func PaddingTypeFactory(PaddingType PaddingType) (SignerItf, error) {
	switch PaddingType {
	case "PKCS":
		return &lib.SignatureTypePKCS{}, nil
	case "PSS":
		return &lib.SignatureTypePSS{}, nil
	default:
		return nil, errors.New("unsupported padding type")
	}
}
