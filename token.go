package pktoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"time"

	jwt "github.com/dgrijalva/jwt-go"
	uuidLib "github.com/hashicorp/go-uuid"
)

// GenerateNewKeyPair ...
func GenerateNewKeyPair() (privateKey *big.Int, publicKeyX *big.Int, publicKeyY *big.Int) {

	generatedPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		fmt.Println(err)
		return nil, nil, nil
	}

	return generatedPrivateKey.D, generatedPrivateKey.PublicKey.X, generatedPrivateKey.PublicKey.Y

}

// SignMessage ...
func SignMessage(privateKeyD *big.Int, publicKeyX *big.Int, publicKeyY *big.Int) (string, error) {

	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     publicKeyX,
		Y:     publicKeyY,
	}

	privateKey := ecdsa.PrivateKey{D: privateKeyD, PublicKey: publicKey}

	uuid, _ := uuidLib.GenerateUUID()
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(60 * time.Second).Unix(),
		Id:        uuid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	return token.SignedString(&privateKey)

}

// ValidateSignedMessage ...
func ValidateSignedMessage(publicKeyX *big.Int, publicKeyY *big.Int, signed string) (bool, error) {

	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     publicKeyX,
		Y:     publicKeyY,
	}

	token, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return &publicKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims.VerifyExpiresAt(time.Now().Unix(), true) {
			return true, nil
		}
	}

	return false, err

}
