package sigma

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type EqProof struct {
	A, B      *Point
	z         *big.Int
	cipher    *Elgamal
	votePower *big.Int
	publicKey *Point
}

func (proof *EqProof) Prove(cipher *Elgamal, random, votePower *big.Int, publicKey *Point) {
	w, err := rand.Int(rand.Reader, S256.Params().N)

	if err != nil {
		fmt.Println("failed to create rand", err)
		panic(err)
	}

	proof.cipher = cipher
	proof.votePower = votePower
	proof.publicKey = publicKey
	proof.A = new(Point).ScalarBaseMult(w)        // A = g^w
	proof.B = new(Point).ScalarMult(publicKey, w) // B = pk^w

	c := createChallangeForEqProof(proof.cipher, proof.A, proof.B, proof.publicKey)

	proof.z = new(big.Int).Sub(w, new(big.Int).Mul(c, random)) // z = w- c.r
}

func (proof *EqProof) Verify() bool {

	// compute c
	c := createChallangeForEqProof(proof.cipher, proof.A, proof.B, proof.publicKey)

	// compute right hand side g^z.C_1^c
	rhs := new(Point).ScalarBaseMult(proof.z)
	rhs.Add(rhs, new(Point).ScalarMult(proof.cipher.left, c))

	// compute inverse of left hand side

	res0 := IsEqual(proof.A, rhs)

	rhs = new(Point).ScalarMult(proof.publicKey, proof.z)
	rhs.Add(rhs, new(Point).ScalarMult(new(Point).Add(proof.cipher.right, new(Point).ScalarBaseMult(new(big.Int).Neg(proof.votePower))), c))

	res1 := IsEqual(proof.B, rhs)
	return res0 && res1
}

func createChallangeForEqProof(cipher *Elgamal, A, B, publicKey *Point) *big.Int {

	digest1 := sha256.New()
	var buffer bytes.Buffer
	buffer.WriteString(cipher.left.X.String())
	buffer.WriteString(cipher.left.Y.String())
	buffer.WriteString(cipher.right.X.String())
	buffer.WriteString(cipher.right.Y.String())
	buffer.WriteString(A.X.String())
	buffer.WriteString(A.Y.String())
	buffer.WriteString(B.X.String())
	buffer.WriteString(B.Y.String())
	buffer.WriteString(publicKey.X.String())
	buffer.WriteString(publicKey.Y.String())
	digest1.Write(buffer.Bytes())
	output1 := digest1.Sum(nil)
	tmp1 := output1[0:]
	return new(big.Int).SetBytes(tmp1)

}
