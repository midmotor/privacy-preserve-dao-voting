package snarks

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type VoteCircuit interface {
	Define(api frontend.API) error
}

type Elgamal interface {
	CheckElGamalEqualityCircuit(api frontend.API, enc1, enc2 any)
	AddVotesCircuit(curve twistededwards.Curve, oldEncVote, addEncVote any) any
	CreateVotesCircuit(curve twistededwards.Curve, value, randoms []frontend.Variable, base, publicKey twistededwards.Point) any
}
