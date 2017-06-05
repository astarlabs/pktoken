package pktoken

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

const (
	privateKeyHeader = "RSA PRIVATE KEY"
	publicKeyHeader  = "RSA PUBLIC KEY"
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
		Type:    privateKeyHeader,
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
		Type:    publicKeyHeader,
		Headers: nil,
		Bytes:   pubDer,
	}
	pubPem := string(pem.EncodeToMemory(&pubBlock))

	return hex.EncodeToString([]byte(privPem)), hex.EncodeToString([]byte(pubPem)), err

}

// SignMessage ...
func SignMessage(privateKey string) (string, error) {

	hexDecoded, err := hex.DecodeString(privateKey)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	block, _ := pem.Decode(hexDecoded)

	if block == nil || block.Type != privateKeyHeader {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	privateKeyInterface, err := parsePKCS(block.Bytes)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	uuid, _ := uuidLib.GenerateUUID()
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
		Id:        uuid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(privateKeyInterface)

}

func parsePKCS(blockBytes []byte) (*rsa.PrivateKey, error) {

	pkcs1, err := x509.ParsePKCS1PrivateKey(blockBytes)
	if err == nil {
		return pkcs1, nil
	}
	pkcs2, err := x509.ParsePKCS8PrivateKey(blockBytes)
	if err == nil {
		return pkcs2.(*rsa.PrivateKey), nil
	}

	return nil, err

}

// ValidateSignedMessage ...
func ValidateSignedMessage(publicKey string, signed string) (bool, error) {

	hexDecoded, err := hex.DecodeString(publicKey)

	if err != nil {
		fmt.Println(err)
		return false, err
	}

	block, _ := pem.Decode(hexDecoded)

	if block == nil || block.Type != publicKeyHeader {
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

	if token.Valid {

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if claims != nil {
				if !claims.VerifyExpiresAt(time.Now().Unix(), true) || claims.VerifyIssuedAt(time.Now().Add(-1*time.Minute).Unix(), true) {
					return false, errors.New("Timing is everything")
				}
				return true, nil
			}
		} else {
			return false, errors.New("Empty Claims")
		}

		return false, errors.New("Invalid Claims")
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return false, errors.New("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return false, errors.New("Timing is everything")
		}
		return false, errors.New(ve.Error())
		//return false, errors.New("Couldn't handle this token")
	} else {
		return false, errors.New(ve.Error())
		//return false, errors.New("Couldn't handle this token")
	}

}
