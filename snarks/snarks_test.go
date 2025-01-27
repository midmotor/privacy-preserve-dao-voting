package snarks

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	_ "github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestGroth(t *testing.T) {
	//create pair
	priv := new(big.Int).SetInt64(100)
	pub := new(bn254.PointAffine).ScalarMultiplication(&Base, priv)
	// priv := new(big.Int).SetInt64(100)

	// weight
	weight := new(big.Int).SetInt64(10)

	// create current bc Votes
	votes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)}
	randoms := []*big.Int{new(big.Int).SetInt64(1111), new(big.Int).SetInt64(1111), new(big.Int).SetInt64(1111), new(big.Int).SetInt64(1111)}
	currentEncVotes := CreateVotes(votes, randoms, pub)

	// create add Votes
	addVotes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int).SetInt64(3), new(big.Int).SetInt64(4)}
	addRandoms := []*big.Int{new(big.Int).SetInt64(111), new(big.Int).SetInt64(222), new(big.Int).SetInt64(333), new(big.Int).SetInt64(444)}
	addEncVotes := CreateVotes(addVotes, addRandoms, pub)

	// create new stage of Votes
	newEncVotes := AddVotes(currentEncVotes, addEncVotes)

	var circuit CircuitMain

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(r1cs)
	assignment := CircuitMain{}

	assignment.VoteWeight = weight
	assignment.MasterPubKey.X = pub.X
	assignment.MasterPubKey.Y = pub.Y

	for i := 0; i < COUNT; i++ {
		assignment.Randoms[i] = addRandoms[i]
		assignment.Vote[i] = addVotes[i]

		assignment.EncVoteNew.ElGamals[i].Left.X = newEncVotes.ElGamals[i].Left.X
		assignment.EncVoteNew.ElGamals[i].Left.Y = newEncVotes.ElGamals[i].Left.Y
		assignment.EncVoteNew.ElGamals[i].Right.X = newEncVotes.ElGamals[i].Right.X
		assignment.EncVoteNew.ElGamals[i].Right.Y = newEncVotes.ElGamals[i].Right.Y

		assignment.EncVoteOld.ElGamals[i].Left.X = currentEncVotes.ElGamals[i].Left.X
		assignment.EncVoteOld.ElGamals[i].Left.Y = currentEncVotes.ElGamals[i].Left.Y
		assignment.EncVoteOld.ElGamals[i].Right.X = currentEncVotes.ElGamals[i].Right.X
		assignment.EncVoteOld.ElGamals[i].Right.Y = currentEncVotes.ElGamals[i].Right.Y
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()

	// create proof
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		t.Fatalf("prove error: %s", err)
	}
	//t.Logf("proof: %+v", proof)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("verify error: %s", err)
	}

}
