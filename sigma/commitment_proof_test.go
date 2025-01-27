package sigma

import (
	"crypto/rand"
	"math/big"
	"testing"
	"voting/bulletproofs"
)

func TestComProof(t *testing.T) {
	x := new(big.Int).SetInt64(2)
	randomCom, _ := rand.Int(rand.Reader, S256.Params().N)
	proof, _ := bulletproofs.Prove(x, randomCom, BULLETPROOF_PARAMS)

	commitment := new(Point)
	commitment.X = proof.V.X
	commitment.Y = proof.V.Y

	randomCipher, _ := rand.Int(rand.Reader, S256.Params().N)
	privateKey, _ := rand.Int(rand.Reader, S256.Params().N)
	publicKey := new(Point).ScalarBaseMult(privateKey)
	cipher := new(Elgamal)
	cipher.Encrypt(x, randomCipher, publicKey)

	commitmentProof := new(ComProof)
	commitmentProof.Prove(cipher.right, commitment, x, randomCom, randomCipher, publicKey)

	res := commitmentProof.Verify()

	if res != true {
		t.Errorf("Assert failure: expected true")
	}

}
