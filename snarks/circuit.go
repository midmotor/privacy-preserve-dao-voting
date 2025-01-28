package snarks

import (
	tedd "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

var elgamal3 VotesCircuit3
var elgamal4 VotesCircuit4
var elgamal5 VotesCircuit5
var elgamal6 VotesCircuit6

var base = twistededwards.Point{X: BASE.X, Y: BASE.Y}

type Circuit3 struct {
	VoteWeight   frontend.Variable    `gnark:",public"`
	MasterPubKey twistededwards.Point `gnark:",public"`
	Vote         [3]frontend.Variable
	Randoms      [3]frontend.Variable
	EncVoteOld   VotesCircuit3 `gnark:",public"`
	EncVoteNew   VotesCircuit3 `gnark:",public"`
}

type Circuit4 struct {
	VoteWeight   frontend.Variable    `gnark:",public"`
	MasterPubKey twistededwards.Point `gnark:",public"`
	Vote         [4]frontend.Variable
	Randoms      [4]frontend.Variable
	EncVoteOld   VotesCircuit4 `gnark:",public"`
	EncVoteNew   VotesCircuit4 `gnark:",public"`
}

type Circuit5 struct {
	VoteWeight   frontend.Variable    `gnark:",public"`
	MasterPubKey twistededwards.Point `gnark:",public"`
	Vote         [5]frontend.Variable
	Randoms      [5]frontend.Variable
	EncVoteOld   VotesCircuit5 `gnark:",public"`
	EncVoteNew   VotesCircuit5 `gnark:",public"`
}

type Circuit6 struct {
	VoteWeight   frontend.Variable    `gnark:",public"`
	MasterPubKey twistededwards.Point `gnark:",public"`
	Vote         [6]frontend.Variable
	Randoms      [6]frontend.Variable
	EncVoteOld   VotesCircuit6 `gnark:",public"`
	EncVoteNew   VotesCircuit6 `gnark:",public"`
}

func (circuit *Circuit3) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedd.BN254)
	if err != nil {
		return err
	}

	insideEncAddVote := elgamal3.CreateVotesCircuit(curve, circuit.Vote[:], circuit.Randoms[:], base, circuit.MasterPubKey)
	insideEncVoteNew := elgamal3.AddVotesCircuit(curve, circuit.EncVoteOld, insideEncAddVote)

	elgamal3.CheckElGamalEqualityCircuit(api, insideEncVoteNew, circuit.EncVoteNew)
	CheckVoteRangeCircuit(api, circuit.VoteWeight, circuit.Vote[:])

	return nil
}

func (circuit *Circuit4) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedd.BN254)
	if err != nil {
		return err
	}

	insideEncAddVote := elgamal4.CreateVotesCircuit(curve, circuit.Vote[:], circuit.Randoms[:], base, circuit.MasterPubKey)
	insideEncVoteNew := elgamal4.AddVotesCircuit(curve, circuit.EncVoteOld, insideEncAddVote)

	elgamal4.CheckElGamalEqualityCircuit(api, insideEncVoteNew, circuit.EncVoteNew)
	CheckVoteRangeCircuit(api, circuit.VoteWeight, circuit.Vote[:])

	return nil
}

func (circuit *Circuit5) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedd.BN254)
	if err != nil {
		return err
	}

	insideEncAddVote := elgamal5.CreateVotesCircuit(curve, circuit.Vote[:], circuit.Randoms[:], base, circuit.MasterPubKey)
	insideEncVoteNew := elgamal5.AddVotesCircuit(curve, circuit.EncVoteOld, insideEncAddVote)

	elgamal5.CheckElGamalEqualityCircuit(api, insideEncVoteNew, circuit.EncVoteNew)
	CheckVoteRangeCircuit(api, circuit.VoteWeight, circuit.Vote[:])

	return nil
}

func (circuit *Circuit6) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedd.BN254)
	if err != nil {
		return err
	}

	insideEncAddVote := elgamal6.CreateVotesCircuit(curve, circuit.Vote[:], circuit.Randoms[:], base, circuit.MasterPubKey)
	insideEncVoteNew := elgamal6.AddVotesCircuit(curve, circuit.EncVoteOld, insideEncAddVote)

	elgamal6.CheckElGamalEqualityCircuit(api, insideEncVoteNew, circuit.EncVoteNew)
	CheckVoteRangeCircuit(api, circuit.VoteWeight, circuit.Vote[:])

	return nil
}
