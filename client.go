package pktoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	jwt "github.com/dgrijalva/jwt-go"
)

/*func main() {

	priv, pubX, pubY := GenerateNewKeyPair()

	signed, err := SignMessage(priv, pubX, pubY, "hello")

	if err != nil {
		fmt.Println(err)
	}

	ok, err := ValidateSignedMessage(pubX, pubY, "hello", signed)

	if !ok {
		fmt.Println(err)
	} else {
		fmt.Println("sucesso")
	}

}*/

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
func SignMessage(privateKeyD *big.Int, publicKeyX *big.Int, publicKeyY *big.Int, message string) (string, error) {

	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     publicKeyX,
		Y:     publicKeyY,
	}

	privateKey := ecdsa.PrivateKey{D: privateKeyD, PublicKey: publicKey}

	claims := &jwt.MapClaims{
		"message": message,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	return token.SignedString(&privateKey)

}

// ValidateSignedMessage ...
func ValidateSignedMessage(publicKeyX *big.Int, publicKeyY *big.Int, message string, signed string) (bool, error) {

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
		if claims["message"] == message {
			return true, nil
		}
	}

	return false, err

}
