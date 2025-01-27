package sigma

import (
	"crypto/rand"
	"math/big"
	"voting/bulletproofs"
)

var H = createH()
var BULLETPROOF_RANGE = 4
var BULLETPROOF_PARAMS, _ = bulletproofs.Setup(int64(BULLETPROOF_RANGE))
var DUMMY_PRIV_KEY = new(big.Int).SetInt64(1234)
var DUMMY_PUB_KEY = new(Point).ScalarBaseMult(DUMMY_PRIV_KEY)

func createRandoms(len int) []*big.Int {
	randoms := make([]*big.Int, len)
	for i := range randoms {
		randoms[i], _ = rand.Int(rand.Reader, S256.Params().N)

	}
	return randoms
}

func createH() *Point {
	X, _ := new(big.Int).SetString("101867493481533935461446799773528889833511765856989950181223576558636703219071", 10)
	Y, _ := new(big.Int).SetString("37885959694882703908442697523821087621294086357243612387745558661534475340673", 10)
	return &Point{X, Y}
}

func createZero() *Point {
	return &Point{new(big.Int).SetInt64(0), new(big.Int).SetInt64(0)}
}

func AddRandoms(randoms []*big.Int) *big.Int {
	result := new(big.Int).SetInt64(0)

	for i := 0; i < len(randoms); i++ {
		result.Add(result, randoms[i])
	}

	return result
}
