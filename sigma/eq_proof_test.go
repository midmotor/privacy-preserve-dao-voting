package sigma

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestEqProof(t *testing.T) {

	vote := new(big.Int).SetInt64(5)
	votePower := new(big.Int).SetInt64(5)
	random, _ := rand.Int(rand.Reader, S256.Params().N)

	privateKey, _ := rand.Int(rand.Reader, S256.Params().N)
	publicKey := new(Point).ScalarBaseMult(privateKey)

	cipher := new(Elgamal)
	cipher.Encrypt(vote, random, publicKey)

	proof := new(EqProof)
	proof.Prove(cipher, random, votePower, publicKey)

	res := proof.Verify()

	if res != true {
		t.Errorf("Assert failure: expected true")
	}
}
