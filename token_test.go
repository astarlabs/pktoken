package pktoken

import (
	"math/big"
	"testing"
)

func Test(t *testing.T) {

	priv, pubX, pubY := GenerateNewKeyPair()

	t.Logf("private key: %s", priv)
	t.Logf("public key: %s", pubX)
	t.Logf("public key: %s", pubY)

	signed, err := SignMessage(priv, pubX, pubY)

	t.Logf("signed message: %s", signed)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	ok, err := ValidateSignedMessage(pubX, pubY, signed)

	if !ok {
		t.Error("1 - invalid")
		t.Fail()
	} else {
		t.Log("1 - valid")
	}

	ok, err = ValidateSignedMessage(pubX, pubY.Add(big.NewInt(15), big.NewInt(10)), signed)

	if !ok {
		t.Error("2 - invalid")
		t.Fail()
	} else {
		t.Log("2 - valid")
	}

	ok, err = ValidateSignedMessage(pubX, pubY, signed+"123")

	if !ok {
		t.Error("3 - invalid")
		t.Fail()
	} else {
		t.Log("3 - valid")
	}

}
