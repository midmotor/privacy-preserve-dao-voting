package sigma

import (
	"voting/bulletproofs"
)

type transaction struct {
	pubKey         *Point
	encryptedVotes []*Elgamal
	comProofs      []*ComProof
	bulletproofs   []*bulletproofs.BulletProof
	eqProofs       *EqProof
}
