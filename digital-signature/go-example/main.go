package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/tokopedia/cryptography-example/digital-signature/go-example/lib"
)

func main() {
	params := `{}`
	privKeyStr, err := ioutil.ReadFile("./key/priv.pem")
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := lib.ParseRsaPrivateKeyFromPemStr(string(privKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	pubKeyStr, err := ioutil.ReadFile("./key/pub.pem")
	if err != nil {
		log.Fatal(err)
	}

	pubKey, err := lib.ParseRsaPublicKeyFromPemStr(string(pubKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	signer := lib.SignatureTypePSS{}
	// signer := SignatureTypePKCS{}
	signature, err := signer.Sign(privKey, params)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(signature)

	err = signer.Verify(pubKey, params, signature)
	fmt.Println("isVerified: ", err == nil)
}
