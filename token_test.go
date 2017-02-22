package pktoken

import (
	"testing"
)

func Test(t *testing.T) {

	priv, pub, err := GenerateNewKeyPair()

	t.Logf("private key: %s", priv)
	t.Logf("public key: %s", pub)

	signed, err := SignMessage(priv)

	t.Logf("signed message: %s", signed)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	ok, err := ValidateSignedMessage(pub, signed)

	if !ok {
		t.Error("1 - invalid")
		t.Fail()
	} else {
		t.Log("1 - valid")
	}

	ok, err = ValidateSignedMessage(pub+"invalid", signed)

	if !ok {
		t.Error("2 - invalid")
		t.Fail()
	} else {
		t.Log("2 - valid")
	}

}
