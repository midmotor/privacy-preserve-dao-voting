package sigma

import (
	"math/big"
	"testing"
	"voting/bulletproofs"
)

func BenchmarkSigma(b *testing.B) {

	testCases := []struct {
		name      string
		votePower *big.Int
		boxNumber int
		votes     []*big.Int
	}{
		{
			"votePower:6, boxNumber:3",
			big.NewInt(6),
			3,
			[]*big.Int{
				big.NewInt(1),
				big.NewInt(2),
				big.NewInt(3),
			}},
		{
			"votePower:8, boxNumber:4",
			new(big.Int).SetInt64(8),
			4,
			[]*big.Int{
				big.NewInt(2),
				big.NewInt(1),
				big.NewInt(3),
				big.NewInt(2),
			}},
		{
			"votePower:5, boxNumber:5",
			new(big.Int).SetInt64(5),
			5,
			[]*big.Int{

				big.NewInt(0),
				big.NewInt(1),
				big.NewInt(2),
				big.NewInt(1),
				big.NewInt(1),
			}},
		{
			"votePower:3, boxNumber:6",
			new(big.Int).SetInt64(3),
			4,
			[]*big.Int{
				big.NewInt(0),
				big.NewInt(0),
				big.NewInt(3),
				big.NewInt(0),
				big.NewInt(0),
				big.NewInt(0),
			}},
	}

	_ = testCases

	for _, tc := range testCases {
		var err error
		cipherRandoms := createRandoms(tc.boxNumber)
		comRandoms := createRandoms(tc.boxNumber)
		tx := new(transaction)
		tx.encryptedVotes = make([]*Elgamal, tc.boxNumber)
		tx.bulletproofs = make([]*bulletproofs.BulletProof, tc.boxNumber)
		tx.comProofs = make([]*ComProof, tc.boxNumber)
		tx.pubKey = DUMMY_PUB_KEY

		for i := 0; i < tc.boxNumber; i++ {
			tx.encryptedVotes[i] = new(Elgamal)
			tx.encryptedVotes[i].Encrypt(tc.votes[i], cipherRandoms[i], DUMMY_PUB_KEY)
		}

		// prove
		b.Run(tc.name+" proving", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for j := 0; j < tc.boxNumber; j++ {
					tx.bulletproofs[j] = new(bulletproofs.BulletProof)
					tx.bulletproofs[j], err = bulletproofs.Prove(tc.votes[j], comRandoms[j], BULLETPROOF_PARAMS)
					if err != nil {
						b.Errorf("failed to create bulletproof")
					}
					commitment := new(Point)
					commitment.X = tx.bulletproofs[j].V.X
					commitment.Y = tx.bulletproofs[j].V.Y

					tx.comProofs[j] = new(ComProof)
					tx.comProofs[j].Prove(tx.encryptedVotes[j].right, commitment, tc.votes[j], comRandoms[j], cipherRandoms[j], DUMMY_PUB_KEY)
				}

				cumulativeCipher := new(Elgamal)
				cumulativeCipher.HomomorphicAdd(tx.encryptedVotes)

				tx.eqProofs = new(EqProof)
				cumulativeRandom := AddRandoms(cipherRandoms)
				tx.eqProofs.Prove(cumulativeCipher, cumulativeRandom, tc.votePower, DUMMY_PUB_KEY)
			}

			b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
		})
		//verify
		b.Run(tc.name+" verifying", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for j := 0; j < tc.boxNumber; j++ {
					res := tx.comProofs[j].Verify()
					if res != true {
						b.Errorf("failed to verify")
					}
					res, _ = tx.bulletproofs[j].Verify()
					if res != true {
						b.Errorf("failed to verify ")
					}
				}
				res := tx.eqProofs.Verify()
				if res != true {
					b.Errorf("failed to verify")
				}
			}

			b.ReportMetric(float64(b.Elapsed())/(1_000_000*float64(b.N)), "ms/op")
		})

	}
}
