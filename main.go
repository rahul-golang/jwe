package main

import (
	"context"
	"crypto/rsa"

	"fmt"
	"github.com/rahul-golang/jwe/crypto_utils"
	. "github.com/square/go-jose/v3"
	"time"
)

func main() {

	utils := crypto_utils.NewCryptoUtils()
	publicKey, err := utils.GetPublicKey(context.Background())
	if err != nil {
		fmt.Println("error in getting public key", err)
	}

	jwetoken := Encrypt(publicKey)
	privateKey, err := utils.GetPrivateKey(context.Background())
	if err != nil {
		fmt.Println("error in getting public key", err)
	}
	Decrypt(privateKey, jwetoken)

}

func Encrypt(publicKey *rsa.PublicKey) string {

	opts := new(EncrypterOptions)
	opts.WithHeader("iat", time.Now().Unix())

	encrypter, err := NewEncrypter(A256GCM, Recipient{Algorithm: RSA_OAEP_256, Key: publicKey}, opts)
	if err != nil {
		panic(err)
	}

	jwe, err := encrypter.Encrypt([]byte(`{"id":"1","name":"rahul"}`))
	if err != nil {
		panic(err)
	}

	jweCompact, err := jwe.CompactSerialize()
	if err != nil {
		panic(err)
	}

	fmt.Println(jweCompact)
	return jweCompact
}

func Decrypt(privateKey *rsa.PrivateKey, jwe string) {
	encryptedJwe, err := ParseEncrypted(jwe)
	if err != nil {
		panic(err)
	}

	decrypted, err := encryptedJwe.Decrypt(privateKey)

	fmt.Println("response: ", string(decrypted))
}
