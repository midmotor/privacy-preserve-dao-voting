package snarks

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

var BASE = bn254.GetEdwardsCurve().Base
var ORDER = bn254.GetEdwardsCurve().Order

type ElGamal struct {
	Left  *bn254.PointAffine
	Right *bn254.PointAffine
}

type Votes struct {
	ElGamals []*ElGamal
}

func NewElGamal(p1, p2 *bn254.PointAffine) *ElGamal {
	p := new(ElGamal)
	p.Left = p1
	p.Right = p2

	return p
}

func NewPoint(x, y *fr.Element) *bn254.PointAffine {
	p := new(bn254.PointAffine)
	p.X = *x
	p.Y = *y

	return p
}

func CreateElGamal(message *big.Int, publicKey *bn254.PointAffine, random *big.Int) *ElGamal {
	left := new(bn254.PointAffine).ScalarMultiplication(&BASE, random)
	right := new(bn254.PointAffine).Add(
		new(bn254.PointAffine).ScalarMultiplication(&BASE, message),
		new(bn254.PointAffine).ScalarMultiplication(publicKey, random))

	return NewElGamal(left, right)
}

func CreateVotes(message, random []*big.Int, publicKey *bn254.PointAffine) *Votes {
	votes := new(Votes)
	votes.ElGamals = make([]*ElGamal, len(random))

	for i := 0; i < len(random); i++ {
		votes.ElGamals[i] = new(ElGamal)
		votes.ElGamals[i] = CreateElGamal(message[i], publicKey, random[i])
	}

	return votes
}

func AddVotes(oldVotes, addVotes *Votes, boxNumber int) *Votes {
	newVotes := new(Votes)
	newVotes.ElGamals = make([]*ElGamal, boxNumber)
	for i := 0; i < boxNumber; i++ {
		newVotes.ElGamals[i] = new(ElGamal)
		newVotes.ElGamals[i].Left = new(bn254.PointAffine).Add(oldVotes.ElGamals[i].Left, addVotes.ElGamals[i].Left)
		newVotes.ElGamals[i].Right = new(bn254.PointAffine).Add(oldVotes.ElGamals[i].Right, addVotes.ElGamals[i].Right)
	}

	return newVotes
}

// (c1,c2) = (g^r, g^m*pk^r)
func DecryptElgamalBrute(enc *ElGamal, sec *big.Int) int {

	dec := new(bn254.PointAffine).Add(
		enc.Right,
		new(bn254.PointAffine).ScalarMultiplication(enc.Left, new(big.Int).Neg(sec)))

	for i := 0; i < 1000; i++ {
		if new(bn254.PointAffine).ScalarMultiplication(&BASE, big.NewInt(int64(i))).X.Equal(&dec.X) {
			return int(i)
		}
	}

	return 99999
}

func createRandoms(len int) []*big.Int {
	randoms := make([]*big.Int, len)
	for i := range randoms {
		randoms[i], _ = rand.Int(rand.Reader, &ORDER)

	}
	return randoms
}
