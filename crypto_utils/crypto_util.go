package crypto_utils

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/square/go-jose"
)

type CryptoUtils interface {
	GetEncrypter(ctx context.Context, publicKey *rsa.PublicKey) (jose.Encrypter, error)
	GetPublicKey(ctx context.Context) (*rsa.PublicKey, error)
	GetPrivateKey(ctx context.Context) (*rsa.PrivateKey, error)
}
type cryptoUtils struct {
}

func (crypto cryptoUtils) GetEncrypter(ctx context.Context, publicKey *rsa.PublicKey) (jose.Encrypter, error) {
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey}, nil)
	if err != nil {
		return nil, err
	}
	return encrypter, err
}

var publicKeyData = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAh7BcU+ZMHqXoYvNFfX1WsuTvaEJzgq31N4brjl09gLAPW6hbr/Jf\nLcJU+KU9tglr9MT5prMXMdSDAM4DXUOusV5C2EJoh5EiSpCrWQXGAfCPV5YYiauu\nISh6KStyZ/jL1fWA2PhuEBkOdYLeQCKRdhjORjqT9GftjuTXRLf70ji/XPal+qeZ\n9TFyFWVP8UZH1U+5AL1qq1aGRrPwoIVjSMMIP20+ONpfFGOCTITrImpL4eq0LLZl\n7n/+N99ijsA5Idr+c2Rwh6tfJIz9FvZ08TjQOiXp7gA+KEYtvFjmBxw54X6ipiP7\n7bbIy3B6EWaR16UceIhxExsi0vFcdt/5JwIDAQAB\n-----END RSA PUBLIC KEY-----"

func (crypto cryptoUtils) GetPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	fmt.Println("CryptoUtils.GetPrivateKey: In get public key function.")
	//fmt.Println(publicKeyData)
	data, _ := pem.Decode([]byte(publicKeyData))
	if data == nil {
		fmt.Errorf(" %s CryptoUtils.Encrypt: Error In pem.Decode() : Public key not found.", "")
		return nil, errors.New("public key not found")
	}
	publicKey, parsingError := x509.ParsePKCS1PublicKey(data.Bytes)
	if parsingError != nil {
		fmt.Errorf("CryptoUtils.Encrypt: Error in public key not parsing: %-v ", parsingError)
		return nil, parsingError
	}
	return publicKey, nil
}

var privateKeyData = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAh7BcU+ZMHqXoYvNFfX1WsuTvaEJzgq31N4brjl09gLAPW6hb\nr/JfLcJU+KU9tglr9MT5prMXMdSDAM4DXUOusV5C2EJoh5EiSpCrWQXGAfCPV5YY\niauuISh6KStyZ/jL1fWA2PhuEBkOdYLeQCKRdhjORjqT9GftjuTXRLf70ji/XPal\n+qeZ9TFyFWVP8UZH1U+5AL1qq1aGRrPwoIVjSMMIP20+ONpfFGOCTITrImpL4eq0\nLLZl7n/+N99ijsA5Idr+c2Rwh6tfJIz9FvZ08TjQOiXp7gA+KEYtvFjmBxw54X6i\npiP77bbIy3B6EWaR16UceIhxExsi0vFcdt/5JwIDAQABAoIBAAdcPrXiYTCsaT2s\n2pEjEmfj2US7jg6BpzKa4/41+pcXdc3QBSE3MYiG6RsPw5gzTKLbaHttbY2rbGvH\nwRD3EevXJCMc/xSTf9uxm0nZ8VK7nNrwbmZRZMGxs2a2T59qNIxno9ShLT88TLd9\nINczyNYyJEZU+R+h35YHvdGhdUyC6TIJws/26U2/bedXt8bMJJh2UoDncYacoLTG\n2YJhkQRShL4Hve8UzjSHSdG0z8/EDK9JjkcazjRKn4Qbv7Li84n7F7erfNXh4YBh\npwoMcUZrkN+Tmee6U3b5AGHw50wjWRnfOmtrdOpCLjO44dRTUETW6wIbmXxrHQoC\nZgx2LiECgYEAztib6nlgf2F+2lDiOPeohtOenlf+ta+/nLGcpihcEfpOMSQS3oUC\nkqoTrav9l20N8UCvmxPp4WmqpLntkClRj+CwrJJauvOoBKBhfHciNk3TK5eSawis\n4B1SOZDZkUXKwGstnBkuw2C0CargO0dFtja9itdn9xkUbI5P0/+9wbcCgYEAp+7v\nKIy/V+IQqiWcSPxbw2lSaWxU0ciFwDgDLd1Cfi1vy3k4h/gzTd4SBRdNP6XQ+tSh\nK1cVJ54MvXaCJXOSWRxk4v+zL/h9PbFhxMS8dSkiJb2wspOBFKRNp3toxj3sWntC\n9l+ZhsaKdGLzpzDgzBAmA3oyb7/xJc3/Nyy6xBECgYBpaB7ENQhEwXU4YaF2sFYU\nJwEc5fCpu57kheozDjwk+S4hgqWO+a8e+EbA6PV41h0VxQX3/ATiVsub2BfEsBmd\nPT4rIwXTYVlMykIDgF5R2AT1oO7/VlNqfeap6TPGAQ/aUIPUmUyoSb5VctuDucU/\nntOmTjDvzbsHutnZSej0LwKBgC1GgNoY4DmMbFvDGhifWQodKifcGh4ZBt5k+45w\n+c1U6LAd9XzLEOHsfkU7HAuN5ALMMsuhhcWRmfO2sK3yM8GsoxKER8YmI3XvjeFj\n/T9FILy2IJ50oDd1eK4v2nagGUnns40DBzxL6OYqC3DG/8Rkkisb1d9FC3nayPUS\nLSRRAoGBAJtCFrhp7CMo4ZOJPXxbS0xpXOjrmIFjCXLE0MyNYFqv8qJVrBRqk/rg\nEXHA0QSkXXZefGhYXIzzqXTBrp2XokFuLCAlmyx3ldZZdFV9Lc+zNkl45UtFcKxE\n19GGQ7s2qQ683Vjt9cAPogvyVwPulBxrIkRfgc2sdytHjQ9xk8oa\n-----END RSA PRIVATE KEY-----"

func (crypto cryptoUtils) GetPrivateKey(ctx context.Context) (*rsa.PrivateKey, error) {
	fmt.Println("CryptoUtils.GetPrivateKey: In get private key function.")
	//fmt.Println("Private Key : ", privateKeyData)
	data, _ := pem.Decode([]byte(privateKeyData))
	if data == nil {
		fmt.Errorf("CryptoUtils.Encrypt: Error In pem.Decode() :%s", " Private key not found.")
		return nil, errors.New("private key not found")
	}
	privateKey, parsingError := x509.ParsePKCS1PrivateKey(data.Bytes)
	if parsingError != nil {
		return nil, parsingError
	}
	return privateKey, nil

}

func NewCryptoUtils() CryptoUtils {
	return &cryptoUtils{}
}
