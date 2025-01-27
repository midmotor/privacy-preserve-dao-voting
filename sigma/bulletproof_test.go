package sigma

import (
	"crypto/rand"
	"math"
	"math/big"
	"testing"
	"voting/bulletproofs"
)

func TestXEqualsRangeStart(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(2)

	params := setupRange(t, rangeEnd)
	if proveAndVerifyRange(x, params) != true {
		t.Errorf("x equal to range start should verify successfully")
	}
}

func setupRange(t *testing.T, rangeEnd int64) bulletproofs.BulletProofSetupParams {
	params, err := bulletproofs.Setup(rangeEnd)

	if err != nil {
		t.Errorf("Invalid range end: %s", err)
		t.FailNow()
	}
	return params
}

func proveAndVerifyRange(x *big.Int, params bulletproofs.BulletProofSetupParams) bool {
	random, _ := rand.Int(rand.Reader, bulletproofs.ORDER)
	proof, _ := bulletproofs.Prove(x, random, params)
	ok, _ := proof.Verify()
	return ok

}
