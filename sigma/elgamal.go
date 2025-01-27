package sigma

import (
	"math/big"
)

type Elgamal struct {
	left   *Point
	right  *Point
	pubkey *Point
}

func (cipher *Elgamal) Encrypt(vote, random *big.Int, pubkey *Point) {

	cipher.pubkey = pubkey
	cipher.left = new(Point).ScalarBaseMult(random)                                                       // r.G
	cipher.right = new(Point).Add(new(Point).ScalarBaseMult(vote), new(Point).ScalarMult(pubkey, random)) // v.G + r.PK

}

func (cipher *Elgamal) HomomorphicAdd(ciphers []*Elgamal) {
	cipher.left = createZero()
	cipher.right = createZero()
	for i := 0; i < len(ciphers); i++ {
		cipher.left.Add(cipher.left, ciphers[i].left)
		cipher.right.Add(cipher.right, ciphers[i].right)
	}
}
