package snarks

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type ElGamalCircuit struct {
	Left  twistededwards.Point
	Right twistededwards.Point
}

type VotesCircuit3 struct {
	ElGamals [3]ElGamalCircuit
}
type VotesCircuit4 struct {
	ElGamals [4]ElGamalCircuit
}

type VotesCircuit5 struct {
	ElGamals [5]ElGamalCircuit
}

type VotesCircuit6 struct {
	ElGamals [6]ElGamalCircuit
}

func CreateElGamalCircuit(curve twistededwards.Curve, value, random frontend.Variable, base, publicKey twistededwards.Point) ElGamalCircuit {
	return ElGamalCircuit{curve.ScalarMul(base, random), curve.Add(curve.ScalarMul(base, value), curve.ScalarMul(publicKey, random))}
}

func AddElGamalCircuit(curve twistededwards.Curve, oldEncVote, addEncVote ElGamalCircuit) ElGamalCircuit {
	return ElGamalCircuit{curve.Add(oldEncVote.Left, addEncVote.Left), curve.Add(oldEncVote.Right, addEncVote.Right)}
}

func CheckVoteRangeCircuit(api frontend.API, weight frontend.Variable, vote []frontend.Variable) {
	var sum frontend.Variable = 0
	for i := 0; i < len(vote); i++ {
		api.AssertIsLessOrEqual(0, vote[i])
		sum = api.Add(sum, vote[i])
	}
	api.AssertIsEqual(sum, weight)
}

func (VotesCircuit3) CreateVotesCircuit(curve twistededwards.Curve, value, randoms []frontend.Variable, base, publicKey twistededwards.Point) VotesCircuit3 {

	votes := VotesCircuit3{}
	for i := 0; i < len(randoms); i++ {
		votes.ElGamals[i] = CreateElGamalCircuit(curve, value[i], randoms[i], base, publicKey)
	}

	return votes
}

func (VotesCircuit3) AddVotesCircuit(curve twistededwards.Curve, oldEncVote, addEncVote VotesCircuit3) VotesCircuit3 {
	newVotes := VotesCircuit3{}
	for i := 0; i < len(oldEncVote.ElGamals); i++ {
		newVotes.ElGamals[i] = AddElGamalCircuit(curve, oldEncVote.ElGamals[i], addEncVote.ElGamals[i])
	}

	return newVotes
}

func (VotesCircuit3) CheckElGamalEqualityCircuit(api frontend.API, enc1, enc2 VotesCircuit3) {

	len0 := len(enc1.ElGamals)
	len1 := len(enc2.ElGamals)

	if int64(len0) != int64(len1) {
		panic("len0 != len1")
	}
	for i := 0; i < len0; i++ {
		api.AssertIsEqual(enc1.ElGamals[i].Left.X, enc2.ElGamals[i].Left.X)
		api.AssertIsEqual(enc1.ElGamals[i].Left.Y, enc2.ElGamals[i].Left.Y)
		api.AssertIsEqual(enc1.ElGamals[i].Right.X, enc2.ElGamals[i].Right.X)
		api.AssertIsEqual(enc1.ElGamals[i].Right.Y, enc2.ElGamals[i].Right.Y)
	}
}

func (VotesCircuit4) CreateVotesCircuit(curve twistededwards.Curve, value, randoms []frontend.Variable, base, publicKey twistededwards.Point) VotesCircuit4 {

	votes := VotesCircuit4{}
	for i := 0; i < len(randoms); i++ {
		votes.ElGamals[i] = CreateElGamalCircuit(curve, value[i], randoms[i], base, publicKey)
	}

	return votes
}

func (VotesCircuit4) AddVotesCircuit(curve twistededwards.Curve, oldEncVote, addEncVote VotesCircuit4) VotesCircuit4 {
	newVotes := VotesCircuit4{}
	for i := 0; i < len(oldEncVote.ElGamals); i++ {
		newVotes.ElGamals[i] = AddElGamalCircuit(curve, oldEncVote.ElGamals[i], addEncVote.ElGamals[i])
	}

	return newVotes
}

func (VotesCircuit4) CheckElGamalEqualityCircuit(api frontend.API, enc1, enc2 VotesCircuit4) {

	len0 := len(enc1.ElGamals)
	len1 := len(enc2.ElGamals)

	if int64(len0) != int64(len1) {
		panic("len0 != len1")
	}
	for i := 0; i < len0; i++ {
		api.AssertIsEqual(enc1.ElGamals[i].Left.X, enc2.ElGamals[i].Left.X)
		api.AssertIsEqual(enc1.ElGamals[i].Left.Y, enc2.ElGamals[i].Left.Y)
		api.AssertIsEqual(enc1.ElGamals[i].Right.X, enc2.ElGamals[i].Right.X)
		api.AssertIsEqual(enc1.ElGamals[i].Right.Y, enc2.ElGamals[i].Right.Y)
	}
}

func (VotesCircuit5) CreateVotesCircuit(curve twistededwards.Curve, value, randoms []frontend.Variable, base, publicKey twistededwards.Point) VotesCircuit5 {

	votes := VotesCircuit5{}
	for i := 0; i < len(randoms); i++ {
		votes.ElGamals[i] = CreateElGamalCircuit(curve, value[i], randoms[i], base, publicKey)
	}

	return votes
}

func (VotesCircuit5) AddVotesCircuit(curve twistededwards.Curve, oldEncVote, addEncVote VotesCircuit5) VotesCircuit5 {
	newVotes := VotesCircuit5{}
	for i := 0; i < len(oldEncVote.ElGamals); i++ {
		newVotes.ElGamals[i] = AddElGamalCircuit(curve, oldEncVote.ElGamals[i], addEncVote.ElGamals[i])
	}

	return newVotes
}

func (VotesCircuit5) CheckElGamalEqualityCircuit(api frontend.API, enc1, enc2 VotesCircuit5) {

	len0 := len(enc1.ElGamals)
	len1 := len(enc2.ElGamals)

	if int64(len0) != int64(len1) {
		panic("len0 != len1")
	}
	for i := 0; i < len0; i++ {
		api.AssertIsEqual(enc1.ElGamals[i].Left.X, enc2.ElGamals[i].Left.X)
		api.AssertIsEqual(enc1.ElGamals[i].Left.Y, enc2.ElGamals[i].Left.Y)
		api.AssertIsEqual(enc1.ElGamals[i].Right.X, enc2.ElGamals[i].Right.X)
		api.AssertIsEqual(enc1.ElGamals[i].Right.Y, enc2.ElGamals[i].Right.Y)
	}
}

func (VotesCircuit6) CreateVotesCircuit(curve twistededwards.Curve, value, randoms []frontend.Variable, base, publicKey twistededwards.Point) VotesCircuit6 {

	votes := VotesCircuit6{}
	for i := 0; i < len(randoms); i++ {
		votes.ElGamals[i] = CreateElGamalCircuit(curve, value[i], randoms[i], base, publicKey)
	}

	return votes
}

func (VotesCircuit6) AddVotesCircuit(curve twistededwards.Curve, oldEncVote, addEncVote VotesCircuit6) VotesCircuit6 {
	newVotes := VotesCircuit6{}
	for i := 0; i < len(oldEncVote.ElGamals); i++ {
		newVotes.ElGamals[i] = AddElGamalCircuit(curve, oldEncVote.ElGamals[i], addEncVote.ElGamals[i])
	}

	return newVotes
}

func (VotesCircuit6) CheckElGamalEqualityCircuit(api frontend.API, enc1, enc2 VotesCircuit6) {

	len0 := len(enc1.ElGamals)
	len1 := len(enc2.ElGamals)

	if int64(len0) != int64(len1) {
		panic("len0 != len1")
	}
	for i := 0; i < len0; i++ {
		api.AssertIsEqual(enc1.ElGamals[i].Left.X, enc2.ElGamals[i].Left.X)
		api.AssertIsEqual(enc1.ElGamals[i].Left.Y, enc2.ElGamals[i].Left.Y)
		api.AssertIsEqual(enc1.ElGamals[i].Right.X, enc2.ElGamals[i].Right.X)
		api.AssertIsEqual(enc1.ElGamals[i].Right.Y, enc2.ElGamals[i].Right.Y)
	}
}
