package pktoken

import "testing"

func Test(t *testing.T) {

	priv, pubX, pubY := GenerateNewKeyPair()

	t.Logf("private key: %s", priv)
	t.Logf("public key: %s", pubX)
	t.Logf("public key: %s", pubY)

	signed, err := SignMessage(priv, pubX, pubY, "hello")

	t.Logf("signed message: %s", signed)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	ok, err := ValidateSignedMessage(pubX, pubY, "hello", signed)

	if !ok {
		t.Error("error")
		t.Fail()
	} else {
		t.Log("success")
	}

}
