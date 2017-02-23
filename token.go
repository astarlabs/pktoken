package pktoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"time"

	"crypto/x509"

	"encoding/hex"

	jwt "github.com/dgrijalva/jwt-go"
	uuidLib "github.com/hashicorp/go-uuid"
)

// GenerateNewKeyPair ...
func GenerateNewKeyPair() (privateKey string, publicKey string, err error) {

	generatedPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	marshalPrivateKey, err := x509.MarshalECPrivateKey(generatedPrivateKey)

	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	encodedPrivateKey := hex.EncodeToString(marshalPrivateKey)

	publicKeyInterface := &generatedPrivateKey.PublicKey
	marshalPublicKey, err := x509.MarshalPKIXPublicKey(publicKeyInterface)

	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	encodedPublicKey := hex.EncodeToString(marshalPublicKey)

	fmt.Println(encodedPublicKey)

	return encodedPrivateKey, encodedPublicKey, nil

}

// SignMessage ...
func SignMessage(privateKey string) (string, error) {

	decodedPrivateKey, err := hex.DecodeString(privateKey)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	privateKeyInterface, err := x509.ParseECPrivateKey(decodedPrivateKey)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	uuid, _ := uuidLib.GenerateUUID()
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(60 * time.Second).Unix(),
		Id:        uuid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	return token.SignedString(privateKeyInterface)

}

// ValidateSignedMessage ...
func ValidateSignedMessage(publicKey string, signed string) (bool, error) {

	decodedPublicKey, err := hex.DecodeString(publicKey)

	if err != nil {
		fmt.Println(err)
		return false, err
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(decodedPublicKey)

	if err != nil {
		fmt.Println(err)
		return false, err
	}

	token, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return publicKeyInterface, nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims != nil {
			if claims.VerifyExpiresAt(time.Now().Unix(), true) {
				return true, nil
			}
		}
		return false, nil
	}

	return false, err

}
