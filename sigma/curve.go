package sigma

import (
	"bytes"
	"crypto/sha256"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ing-bank/zkrp/util/bn"
	"github.com/ing-bank/zkrp/util/byteconversion"
	"math/big"
)

type Point struct {
	X, Y *big.Int
}

var (
	S256 = crypto.S256()
)

func (p *Point) IsZero() bool {
	c1 := p.X == nil || p.Y == nil
	if !c1 {
		z := new(big.Int).SetInt64(0)
		return p.X.Cmp(z) == 0 && p.Y.Cmp(z) == 0
	}

	return true
}

/*
Neg returns the inverse of the given elliptic curve point.
*/
func (p *Point) Neg(a *Point) *Point {
	// (X, Y) -> (X, X + Y)
	if a.IsZero() {
		return p.SetInfinity()
	}
	one := new(big.Int).SetInt64(1)
	mone := new(big.Int).Sub(S256.Params().N, one)
	p.ScalarMult(p, mone)
	return p
}

/*
Input points must be distinct
*/
func (p *Point) Add(a, b *Point) *Point {
	if a.IsZero() {
		p.X = b.X
		p.Y = b.Y
		return p
	} else if b.IsZero() {
		p.X = b.X
		p.Y = b.Y
		return p

	}
	resx, resy := S256.Add(a.X, a.Y, b.X, b.Y)
	p.X = resx
	p.Y = resy
	return p
}

/*
Double returns 2*P, where P is the given elliptic curve point.
*/
func (p *Point) Double(a *Point) *Point {
	if a.IsZero() {
		return p.SetInfinity()
	}
	resx, resy := S256.Double(a.X, a.Y)
	p.X = resx
	p.Y = resy
	return p
}

/*
ScalarMul encapsulates the scalar Multiplication Algorithm from secP256k1.
*/
func (p *Point) ScalarMult(a *Point, n *big.Int) *Point {
	if a.IsZero() {
		return p.SetInfinity()
	}
	cmp := n.Cmp(big.NewInt(0))
	if cmp == 0 {
		return p.SetInfinity()
	}
	n = bn.Mod(n, S256.Params().N)
	bns := n.Bytes()
	resx, resy := S256.ScalarMult(a.X, a.Y, bns)
	p.X = resx
	p.Y = resy
	return p
}

/*
ScalarBaseMult returns the Scalar Multiplication by the base generator.
*/
func (p *Point) ScalarBaseMult(n *big.Int) *Point {
	cmp := n.Cmp(big.NewInt(0))
	if cmp == 0 {
		return p.SetInfinity()
	}
	n = bn.Mod(n, S256.Params().N)
	bns := n.Bytes()
	resx, resy := S256.ScalarBaseMult(bns)
	p.X = resx
	p.Y = resy
	return p
}

/*
SetInfinity sets the given elliptic curve point to the point at infinity.
*/
func (p *Point) SetInfinity() *Point {
	p.X = nil
	p.Y = nil
	return p
}

func (p *Point) String() string {
	return "P256(" + p.X.String() + "," + p.Y.String() + ")"
}

/*
Hash is responsible for the computing a Zp element given the input string.
*/
func HashToInt(b bytes.Buffer) (*big.Int, error) {
	digest := sha256.New()
	digest.Write(b.Bytes())
	output := digest.Sum(nil)
	tmp := output[0:]
	return byteconversion.FromByteArray(tmp)
}

func (p *Point) IsOnCurve() bool {
	// y² = x³ + 7
	y2 := new(big.Int).Mul(p.Y, p.Y)
	y2.Mod(y2, S256.Params().P)

	x3 := new(big.Int).Mul(p.X, p.X)
	x3.Mul(x3, p.X)

	x3.Add(x3, new(big.Int).SetInt64(7))
	x3.Mod(x3, S256.Params().P)

	return x3.Cmp(y2) == 0
}

func IsEqual(a, b *Point) bool {
	if (a.X.Cmp(b.X) == 0) && (a.Y.Cmp(b.Y) == 0) {
		return true
	}
	return false
}
