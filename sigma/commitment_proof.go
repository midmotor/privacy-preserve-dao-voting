package sigma

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type ComProof struct {
	A, B        *Point
	z1, z2, z3  *big.Int
	cipherRight *Point
	com         *Point
	publicKey   *Point
}

func (proof *ComProof) Prove(cipherRight, com *Point, vote, randomCom, randomCipher *big.Int, publicKey *Point) {
	w1, err := rand.Int(rand.Reader, S256.Params().N)
	w2, err := rand.Int(rand.Reader, S256.Params().N)
	w3, err := rand.Int(rand.Reader, S256.Params().N)

	if err != nil {
		fmt.Println("failed to create rand", err)
		panic(err)
	}

	proof.cipherRight = cipherRight
	proof.com = com
	proof.publicKey = publicKey
	proof.A = new(Point).Add(new(Point).ScalarBaseMult(w1), new(Point).ScalarMult(H, w2))         // A = g^w_1.h^w_2
	proof.B = new(Point).Add(new(Point).ScalarBaseMult(w1), new(Point).ScalarMult(publicKey, w3)) // B = g^w_1.pk^w_3

	c := createChallangeForComProof(proof.cipherRight, proof.com, proof.A, proof.B, proof.publicKey)

	proof.z1 = new(big.Int).Add(w1, new(big.Int).Mul(c, vote))         // z_1 = w_1 + c.m
	proof.z2 = new(big.Int).Add(w2, new(big.Int).Mul(c, randomCom))    // z_2 = w_2 + c.r'
	proof.z3 = new(big.Int).Add(w3, new(big.Int).Mul(c, randomCipher)) // z_3 = w_3 + c.r

}

func (proof *ComProof) Verify() bool {

	// compute c
	c := createChallangeForComProof(proof.cipherRight, proof.com, proof.A, proof.B, proof.publicKey)

	//compute left hand side A.C^c
	lhs := new(Point).Add(proof.A, new(Point).ScalarMult(proof.com, c))

	// compute right hand side g^z.C_1^c
	rhs := new(Point).Add(new(Point).ScalarBaseMult(proof.z1), new(Point).ScalarMult(H, proof.z2))

	res0 := IsEqual(lhs, rhs)

	lhs = new(Point).Add(proof.B, new(Point).ScalarMult(proof.cipherRight, c))
	rhs = new(Point).Add(new(Point).ScalarBaseMult(proof.z1), new(Point).ScalarMult(proof.publicKey, proof.z3))

	res1 := IsEqual(lhs, rhs)
	return res0 && res1
}

func createChallangeForComProof(cipherRight, com *Point, A, B, publicKey *Point) *big.Int {

	digest1 := sha256.New()
	var buffer bytes.Buffer
	buffer.WriteString(cipherRight.X.String())
	buffer.WriteString(cipherRight.Y.String())
	buffer.WriteString(com.X.String())
	buffer.WriteString(com.Y.String())
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
