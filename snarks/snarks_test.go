package snarks

import (
	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	_ "github.com/consensys/gnark/frontend/cs/r1cs"
	"math/big"
	"testing"
)

func BenchmarkGrothBox3(b *testing.B) {

	boxNumber := 3
	//create pair
	priv := new(big.Int).SetInt64(100)
	pub := new(bn254.PointAffine).ScalarMultiplication(&BASE, priv)
	// priv := new(big.Int).SetInt64(100)

	// votePower
	votePower := new(big.Int).SetInt64(6)

	// create current bc Votes
	votes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)}
	randoms := createRandoms(boxNumber)
	currentEncVotes := CreateVotes(votes, randoms, pub)

	var circuit Circuit3

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, _ := groth16.Setup(r1cs)

	var publicWitness witness.Witness
	var proof groth16.Proof
	b.Run("prove  boxNumber3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// create add Votes
			addVotes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int).SetInt64(3)}
			addRandoms := createRandoms(boxNumber)
			addEncVotes := CreateVotes(addVotes, addRandoms, pub)

			// create new stage of Votes
			newEncVotes := AddVotes(currentEncVotes, addEncVotes, boxNumber)

			assignment := Circuit3{}

			assignment.VoteWeight = votePower
			assignment.MasterPubKey.X = pub.X
			assignment.MasterPubKey.Y = pub.Y

			for i := 0; i < boxNumber; i++ {
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
			publicWitness, err = witness.Public()

			proof, err = groth16.Prove(r1cs, pk, witness)
			if err != nil {
				b.Fatalf("prove error: %s", err)
			}
		}

		b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
	})

	b.Run("verify  boxNumber3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = groth16.Verify(proof, vk, publicWitness)
			if err != nil {
				b.Fatalf("verify error: %s", err)
			}
		}
		b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
	})

	println("number of constraints 3 :", r1cs.GetNbConstraints())

}

func BenchmarkGrothBox4(b *testing.B) {

	boxNumber := 4
	//create pair
	priv := new(big.Int).SetInt64(100)
	pub := new(bn254.PointAffine).ScalarMultiplication(&BASE, priv)
	// priv := new(big.Int).SetInt64(100)

	// votePower
	votePower := new(big.Int).SetInt64(10)

	// create current bc Votes
	votes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)}
	randoms := createRandoms(boxNumber)
	currentEncVotes := CreateVotes(votes, randoms, pub)

	var circuit Circuit4

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, _ := groth16.Setup(r1cs)

	var publicWitness witness.Witness
	var proof groth16.Proof
	b.Run("prove  boxNumber4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// create add Votes
			addVotes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int).SetInt64(3), new(big.Int).SetInt64(4)}
			addRandoms := createRandoms(boxNumber)
			addEncVotes := CreateVotes(addVotes, addRandoms, pub)

			// create new stage of Votes
			newEncVotes := AddVotes(currentEncVotes, addEncVotes, boxNumber)

			assignment := Circuit4{}

			assignment.VoteWeight = votePower
			assignment.MasterPubKey.X = pub.X
			assignment.MasterPubKey.Y = pub.Y

			for i := 0; i < boxNumber; i++ {
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
			publicWitness, err = witness.Public()

			proof, err = groth16.Prove(r1cs, pk, witness)
			if err != nil {
				b.Fatalf("prove error: %s", err)
			}
		}

		b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
	})

	b.Run("verify  boxNumber4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = groth16.Verify(proof, vk, publicWitness)
			if err != nil {
				b.Fatalf("verify error: %s", err)
			}
		}
		b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
	})

	println("number of constraints 4 :", r1cs.GetNbConstraints())

}

func BenchmarkGrothBox5(b *testing.B) {

	boxNumber := 5
	//create pair
	priv := new(big.Int).SetInt64(100)
	pub := new(bn254.PointAffine).ScalarMultiplication(&BASE, priv)
	// priv := new(big.Int).SetInt64(100)

	// votePower
	votePower := new(big.Int).SetInt64(10)

	// create current bc Votes
	votes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)}
	randoms := createRandoms(boxNumber)
	currentEncVotes := CreateVotes(votes, randoms, pub)

	var circuit Circuit5

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, _ := groth16.Setup(r1cs)

	var publicWitness witness.Witness
	var proof groth16.Proof
	b.Run("prove  boxNumber5", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// create add Votes
			addVotes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int).SetInt64(3), new(big.Int).SetInt64(1), new(big.Int).SetInt64(3)}
			addRandoms := createRandoms(boxNumber)
			addEncVotes := CreateVotes(addVotes, addRandoms, pub)

			// create new stage of Votes
			newEncVotes := AddVotes(currentEncVotes, addEncVotes, boxNumber)

			assignment := Circuit5{}

			assignment.VoteWeight = votePower
			assignment.MasterPubKey.X = pub.X
			assignment.MasterPubKey.Y = pub.Y

			for i := 0; i < boxNumber; i++ {
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
			publicWitness, err = witness.Public()

			proof, err = groth16.Prove(r1cs, pk, witness)
			if err != nil {
				b.Fatalf("prove error: %s", err)
			}
		}

		b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
	})

	b.Run("verify  boxNumber5", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = groth16.Verify(proof, vk, publicWitness)
			if err != nil {
				b.Fatalf("verify error: %s", err)
			}
		}
		b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
	})

	println("number of constraints 5 :", r1cs.GetNbConstraints())

}

func BenchmarkGrothBox6(b *testing.B) {

	boxNumber := 6
	//create pair
	priv := new(big.Int).SetInt64(100)
	pub := new(bn254.PointAffine).ScalarMultiplication(&BASE, priv)
	// priv := new(big.Int).SetInt64(100)

	// votePower
	votePower := new(big.Int).SetInt64(10)

	// create current bc Votes
	votes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)}
	randoms := createRandoms(boxNumber)
	currentEncVotes := CreateVotes(votes, randoms, pub)

	var circuit Circuit6

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, _ := groth16.Setup(r1cs)

	var publicWitness witness.Witness
	var proof groth16.Proof
	b.Run("prove  boxNumber6", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// create add Votes
			addVotes := []*big.Int{new(big.Int).SetInt64(1), new(big.Int).SetInt64(2), new(big.Int).SetInt64(3), new(big.Int).SetInt64(1), new(big.Int).SetInt64(1), new(big.Int).SetInt64(2)}
			addRandoms := createRandoms(boxNumber)
			addEncVotes := CreateVotes(addVotes, addRandoms, pub)

			// create new stage of Votes
			newEncVotes := AddVotes(currentEncVotes, addEncVotes, boxNumber)

			assignment := Circuit6{}

			assignment.VoteWeight = votePower
			assignment.MasterPubKey.X = pub.X
			assignment.MasterPubKey.Y = pub.Y

			for i := 0; i < boxNumber; i++ {
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
			publicWitness, err = witness.Public()

			proof, err = groth16.Prove(r1cs, pk, witness)
			if err != nil {
				b.Fatalf("prove error: %s", err)
			}
		}

		b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
	})

	b.Run("verify  boxNumber6", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = groth16.Verify(proof, vk, publicWitness)
			if err != nil {
				b.Fatalf("verify error: %s", err)
			}
		}
		b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
	})

	println("number of constraints 6 :", r1cs.GetNbConstraints())

}
