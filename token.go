package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"time"

	"encoding/pem"

	"encoding/hex"

	jwt "github.com/dgrijalva/jwt-go"
	uuidLib "github.com/hashicorp/go-uuid"
)

// GenerateNewKeyPair ...
func GenerateNewKeyPair() (privateKey string, publicKey string, err error) {

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	err = priv.Validate()
	if err != nil {
		fmt.Println("Validation failed.", err)
	}

	privDer := x509.MarshalPKCS1PrivateKey(priv)

	privblock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}

	privPem := string(pem.EncodeToMemory(&privblock))

	pub := priv.PublicKey
	pubDer, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		fmt.Println("Failed to get der format for PublicKey.", err)
		return
	}

	pubBlock := pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   pubDer,
	}
	pubPem := string(pem.EncodeToMemory(&pubBlock))

	return privPem, hex.EncodeToString([]byte(pubPem)), err

}

// SignMessage ...
func SignMessage(privateKey string) (string, error) {

	block, _ := pem.Decode([]byte(privateKey))

	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	privateKeyInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	uuid, _ := uuidLib.GenerateUUID()
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(60 * time.Second).Unix(),
		Id:        uuid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(privateKeyInterface)

}

// ValidateSignedMessage ...
func ValidateSignedMessage(publicKey string, signed string) (bool, error) {

	eta, _ := hex.DecodeString(publicKey)

	block, _ := pem.Decode(eta)

	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return false, errors.New("failed to decode PEM block containing public key")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		fmt.Println(err)
		return false, err
	}

	token, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
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
