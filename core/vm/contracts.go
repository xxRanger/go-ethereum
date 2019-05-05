// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/bn256"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/crypto/ripemd160"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64  // RequiredPrice calculates the contract gas use
	Run(input []byte) ([]byte, error) // Run runs the precompiled contract
}

// PrecompiledContractsHomestead contains the default set of pre-compiled Ethereum
// contracts used in the Frontier and Homestead releases.
var PrecompiledContractsHomestead = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
}

// PrecompiledContractsByzantium contains the default set of pre-compiled Ethereum
// contracts used in the Byzantium release.
var PrecompiledContractsByzantium = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{},
	common.BytesToAddress([]byte{6}): &verifyProof{},
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func RunPrecompiledContract(p PrecompiledContract, input []byte, contract *Contract) (ret []byte, err error) {
	gas := p.RequiredGas(input)
	if contract.UseGas(gas) {
		return p.Run(input)
	}
	return nil, ErrOutOfGas
}

// ECRECOVER implemented as a native contract.
type ecrecover struct{}

func (c *ecrecover) RequiredGas(input []byte) uint64 {
	return params.EcrecoverGas
}

func (c *ecrecover) Run(input []byte) ([]byte, error) {
	const ecRecoverInputLength = 128

	input = common.RightPadBytes(input, ecRecoverInputLength)
	// "input" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// tighter sig s values input homestead only apply to tx sigs
	if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		return nil, nil
	}
	// v needs to be at the end for libsecp256k1
	pubKey, err := crypto.Ecrecover(input[:32], append(input[64:128], v))
	// make sure the public key is a valid one
	if err != nil {
		return nil, nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32), nil
}

// SHA256 implemented as a native contract.
type sha256hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Sha256PerWordGas + params.Sha256BaseGas
}
func (c *sha256hash) Run(input []byte) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}

// RIPEMD160 implemented as a native contract.
type ripemd160hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *ripemd160hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Ripemd160PerWordGas + params.Ripemd160BaseGas
}
func (c *ripemd160hash) Run(input []byte) ([]byte, error) {
	ripemd := ripemd160.New()
	ripemd.Write(input)
	return common.LeftPadBytes(ripemd.Sum(nil), 32), nil
}

// data copy implemented as a native contract.
type dataCopy struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *dataCopy) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.IdentityPerWordGas + params.IdentityBaseGas
}
func (c *dataCopy) Run(in []byte) ([]byte, error) {
	return in, nil
}

// bigModExp implements a native big integer exponential modular operation.
type bigModExp struct{}

var (
	big1      = big.NewInt(1)
	big4      = big.NewInt(4)
	big8      = big.NewInt(8)
	big16     = big.NewInt(16)
	big32     = big.NewInt(32)
	big64     = big.NewInt(64)
	big96     = big.NewInt(96)
	big480    = big.NewInt(480)
	big1024   = big.NewInt(1024)
	big3072   = big.NewInt(3072)
	big199680 = big.NewInt(199680)
)

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bigModExp) RequiredGas(input []byte) uint64 {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Retrieve the head 32 bytes of exp for the adjusted exponent length
	var expHead *big.Int
	if big.NewInt(int64(len(input))).Cmp(baseLen) <= 0 {
		expHead = new(big.Int)
	} else {
		if expLen.Cmp(big32) > 0 {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), 32))
		} else {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), expLen.Uint64()))
		}
	}
	// Calculate the adjusted exponent length
	var msb int
	if bitlen := expHead.BitLen(); bitlen > 0 {
		msb = bitlen - 1
	}
	adjExpLen := new(big.Int)
	if expLen.Cmp(big32) > 0 {
		adjExpLen.Sub(expLen, big32)
		adjExpLen.Mul(big8, adjExpLen)
	}
	adjExpLen.Add(adjExpLen, big.NewInt(int64(msb)))

	// Calculate the gas cost of the operation
	gas := new(big.Int).Set(math.BigMax(modLen, baseLen))
	switch {
	case gas.Cmp(big64) <= 0:
		gas.Mul(gas, gas)
	case gas.Cmp(big1024) <= 0:
		gas = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(gas, gas), big4),
			new(big.Int).Sub(new(big.Int).Mul(big96, gas), big3072),
		)
	default:
		gas = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(gas, gas), big16),
			new(big.Int).Sub(new(big.Int).Mul(big480, gas), big199680),
		)
	}
	gas.Mul(gas, math.BigMax(adjExpLen, big1))
	gas.Div(gas, new(big.Int).SetUint64(params.ModExpQuadCoeffDiv))

	if gas.BitLen() > 64 {
		return math.MaxUint64
	}
	return gas.Uint64()
}

func (c *bigModExp) Run(input []byte) ([]byte, error) {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Handle a special case when both the base and mod length is zero
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	// Retrieve the operands and execute the exponentiation
	var (
		base = new(big.Int).SetBytes(getData(input, 0, baseLen))
		exp  = new(big.Int).SetBytes(getData(input, baseLen, expLen))
		mod  = new(big.Int).SetBytes(getData(input, baseLen+expLen, modLen))
	)
	if mod.BitLen() == 0 {
		// Modulo 0 is undefined, return zero
		return common.LeftPadBytes([]byte{}, int(modLen)), nil
	}
	return common.LeftPadBytes(base.Exp(base, exp, mod).Bytes(), int(modLen)), nil
}

// newCurvePoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.

// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.

var (
	// true32Byte is returned if the bn256 pairing check succeeds.
	true32Byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// false32Byte is returned if the bn256 pairing check fails.
	false32Byte = make([]byte, 32)

	// errBadPairingInput is returned if the bn256 pairing input is invalid.
	errBadPairingInput = errors.New("bad elliptic curve pairing size")
)

const (
	BLOCK_SIZE = 8192
	Q_SIZE     = 512
	NU_SIZE    = 80
)

type User struct {
	X          *big.Int
	Sigmas     []*bn256.G1
	FileBlocks [][BLOCK_SIZE]byte
	PBParams   *PublicParams
}

type PublicParams struct {
	P *big.Int
	Q *big.Int

	V    *bn256.G2
	EUV  *bn256.GT
	G    *bn256.G2
	G1   *bn256.G1
	U    *bn256.G1
	Name *big.Int
	N    int

	// used for hash func HashIntToG1
	a *big.Int
	b *big.Int

	// used for hash func HashIntToGT
	a1 *big.Int
	b1 *big.Int

	// used for hash func HashGTtoInt
	a2 *big.Int
	b2 *big.Int
	gt *bn256.GT
}

func (this *PublicParams) InitHashFuncParams() {
	a, _ := new(big.Int).SetString("4328940238490234", 10)
	b, _ := new(big.Int).SetString("84392048902", 10)

	a1, _ := new(big.Int).SetString("4283984239058", 10)
	b1, _ := new(big.Int).SetString("434294892038", 10)

	a2, _ := new(big.Int).SetString("44358809435", 10)
	b2, _ := new(big.Int).SetString("989080945", 10)

	this.a = a
	this.a1 = a1
	this.a2 = a2
	this.b = b
	this.b1 = b1
	this.b2 = b2
}

func (this *PublicParams) HashIntToG1(x *big.Int) (*bn256.G1, error) {
	val := new(big.Int).Mul(this.a, x)
	val = val.Add(val, this.b)
	val.Mod(val, this.Q)
	val.Mod(val, this.P)

	return new(bn256.G1).ScalarBaseMult(val), nil
}

func (this *PublicParams) HashIntToGT(x *big.Int) (*bn256.GT, error) {
	val := new(big.Int).Mul(this.a1, x)
	val = val.Add(val, this.b1)
	val.Mod(val, this.Q)
	val.Mod(val, this.P)

	return new(bn256.GT).ScalarMult(this.gt, val), nil
}

func (this *PublicParams) HashGTToInt(p *bn256.GT) (*big.Int, error) {
	// bottom half ^ top half
	data := p.Marshal()
	mid := len(data)/2 + 1
	topHalf := new(big.Int).SetBytes(data[:mid])
	bottomHalf := new(big.Int).SetBytes(data[mid:])
	x := new(big.Int).Xor(topHalf, bottomHalf)

	// calculate sha256
	h := sha256.New()
	h.Write(x.Bytes())
	x = new(big.Int).SetBytes(h.Sum(nil))

	val := new(big.Int).Mul(this.a2, x)
	val = val.Add(val, this.b2)
	val.Mod(val, this.Q)
	val.Mod(val, this.P)

	return val, nil
}

func NewUser(p *big.Int) (*User, error) {
	//sample x
	x, _ := new(big.Int).SetString("7221083416328253539186923529149887519343580056257836412572983956932366122566315642387630696698629996336184769252307102185361834745086771101318373786809551", 10)

	return &User{
		X: x,
	}, nil
}

func (this *User) GenPublicParameter(q *big.Int, p *big.Int) (*PublicParams, error) {
	// sample u
	uB, err := hex.DecodeString("360fff32ba0ee2528c7561125c78b8307e3126a9f9e7c7f2d88ae97da387dd6203abfddc7b6aadbaa562a9d2842f2b1a54a39518a6142f67c1c31c44bce0734e")
	if err != nil {
		return nil, err
	}
	u, ok := new(bn256.G1).Unmarshal(uB)
	if !ok {
		return nil, errors.New("can not unmarshal")
	}

	// g is generator of G2
	g := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	v := new(bn256.G2).ScalarMult(g, this.X)

	euv := bn256.Pair(u, v)
	name, _ := new(big.Int).SetString("40543972481696094343738412477213284309049120307242945390944903096464044401084", 10)

	return &PublicParams{
		P:    p,
		Q:    q,
		V:    v,
		EUV:  euv,
		G:    g,
		G1:   g1,
		U:    u,
		Name: name,
	}, nil
}

func (this *User) GenSigma(fbs [][BLOCK_SIZE]byte) ([]*bn256.G1, error) {
	sigmaArr := make([]*bn256.G1, len(fbs))
	for i, b := range fbs {
		name := this.PBParams.Name.Bytes()
		var wiB bytes.Buffer
		_, err := wiB.Write(name)
		if err != nil {
			return nil, err
		}
		_, err = wiB.Write(big.NewInt(int64(i)).Bytes())
		if err != nil {
			return nil, err
		}
		wi := new(big.Int).SetBytes(wiB.Bytes())
		mi := new(big.Int).Mod(new(big.Int).SetBytes(b[:]), this.PBParams.P)
		umi := new(bn256.G1).ScalarMult(this.PBParams.U, mi)
		hi, err := this.PBParams.HashIntToG1(wi)
		if err != nil {
			return nil, err
		}
		//set sigma
		sigma := new(bn256.G1).Add(hi, umi)
		sigma.ScalarMult(sigma, this.X)
		sigmaArr[i] = sigma
	}
	return sigmaArr, nil
}

func genFileBlock(num int) ([][BLOCK_SIZE]byte, error) {
	fileBlock := make([][BLOCK_SIZE]byte, num)
	fake, err := hex.DecodeString("fffbf5c20f0f6b6b4c2a748f0b543fd7674b8fca30fafbd5eb6cc60a51030318ec2a1b79362cd255f8f8b58d85b9c18393be20a393e6c0904366466c86424c4028c76818a236c710dbed33b424955e4bba20e709e6132bebbf8e3cfcc76308bc547ce634cd2fa36c180a0c134fea1d64863cad1ceb63be578dcaacdfd48f0149e4dc7d63cb5ca2dca065b21364de6cc45769d01ae1386936d50d67c94f91168363b6ac4a2a1c2a5e08ccb985804bc660e793f8f8b4f0172887656e64a46271300c93d40da6dcf97307b043dd24ecd1e5db0ab3d5abe3f084a89cf8e35fb59ce767eda3b7dbe476d76dbcddcc5f2fe16ae03907acb7e96d0e44fe1ec64ecc70bf286d5cfc899a27bbf1f22e607ad72a655800da331cf7837f215dc2efb1398c863cdc29bddac60aed477d67a00a0fcd96d93ec21736dab08b992c6e8184bf11250dd166feb94216fddf08069c4c83a3d863661332d7f9b8a10953a43ef6a150c93be6302d2a38e3ed08bbdaa70e615ec2f2ff9458b45cdb47ed5ee2a90875f3997fe90e8d5d41d82d62a46aa471e4bd381017da331c416729e9bd47a983b8378a2a1872b7ecf945b1be622a55b373b93b271a35548bc52afdb2bb500d1dc6cb59f99c2aad37313a5b4191ee5b3c2466181e88d05ca3ce8a8e84ff7b428f3f0a9611d807017af3a9e0641d35867a5c7671a8c6f4f89b679e168ab46c844353ae8a582de972c3d9afb7731aad933311c88aa08d38facb254ebb1ad0a14498c459b2a58236740758564d7d94b0278279a556f4c67c788eb36abc96ba3f7186a84be39e087ac95e1577a62ccbc03868921c82dc22ff21ed61bfafced46c0b7fef368898c5a9292aa1c85f373728cdb127665db687b6fccb0069462269a3c0c89684f8d8f1aa9c811681f6fe5e66234ac141c0609e3f7e096d3c439a1b7ccaece4769c91d00b6c77d9ae94f4470ce40f330119dc38529db556ff5cfa339af3a9ce95837ab584ee35a0d0990ed2cd7d098d50758c0f70d09f14dd35534508f57d33c7dd9b6fe7c054e0d4829f3f8c003ca70137abbb1d22c1bb4ef8d68fb90920a0dab1778265eb736dcbff994bc9b13d7181faba58eeab1908042c9c93eb431353b3a78f515a1f4150c57bf4b58e9201c03fc02950755f16dac4781f0794f4bb0150b8ef21a315b875e711ca023ee920f9978cdeff8a1d52a5592045f2979fe0b4a997e8cd91f6539148e0bf4e667364a74385d75fa01bd1c478f5bd0ca0b0e83569ee698d28722b88c7506e57082e7ecd1800a86c6f13e21227cd53b90cf132507d185bde1507321d4f552ba7c1c8023f62967dcb0a3384240d67cb66e187cb3a0b57b5ef008fc1338a4c33f9ba747a80f8f41a21d29caa9f7fd628e3532212451f49576c4590fd3c53230101b64f6242e1231561bf5be43fd93273af6b30844508d770511757bf0b9370e9ed5e90e2fc0661e3a505294c47c8ade7554d5eadb00452936dfe1cdc3b7348d1a0ba804e85a5ddf3071e023139ec5487937b2deb17452cf204c93ada31215d35afb1362a357a310105c939850c3410caf5cbfba6e39535e2049538b0fdfa32ce3afde4c22d6447612c78b1219ff9f61a5d91629017da4643cb17ad24f61eed445ae4d69a0a22122b944770aab516c8104f71d2adbfeb51eb96871a832132fb6787ff8a8ed4075e2b8595908660745c6b1c84e47942f8d61b83bb97a704a60dc2cc6dee42a8dcbcadaec4589b6f690b8e998e4992c6c7cb0e320ae32860c899b3bde37e300a4cd08f28d311cfdae220ef19f88f57fe90f8082fd462a96f1bb9e33f20dd0b4327dfc60826b0f917463c06bea150b14f9a19990a6f3a6b241bac02b58a8f483d3af3651ebea2bd30f0b9c7b19a14ca42456fc3c2345545560c262b4dd4c6bbcb67710cd15e4c70a82bad724268ee2c0016926340da7fa8f0a98577e40c60d848efe6a2cd5e9a5e00155e7675b23c043d2918d24328f9a38520965f512908e6b58410c93d7652a1247d3c2addb407a0b556898459b40386823b71d1885971737cc8add64a14a6c287e87a4a0f19763c2461d3a3c2e0c97a94525b903105ac04228fd420742ac47b8693dfa65233f51b196be29741aea6f5bd7482ad6f16a2a78a4c8e242fbc0fbf7c28e369940131db8522ff5779d55a913fc23cc3344d5be51166c3b9afa50433997c9d3f4c568adc524497865e841a6b309866b0037d81494172f65ffd7b98def87bc591efbe2fffa3dbc93775669625c95a1e817d416e2d393ddc73d20abe7478e4a16e83cd941dfbb0fe3b14bb4ddeccb9f80dc67bc43eb8edadd77c21fc5c779084e851f293c7f68a27cbb3fc88a3da8ea2b17f6f7bcdf7235dabb9a91e221d1a17855e969ab8b12daa6666a35d464e4b2fc019e14f5f1fb666ccebb3555acc2b77cbf7f963de28b5bf2ca4c804291f7f070c4fd2471c98f5a164017745596a4c848bb5b373b780a135cc5f3415e333ce072eb02cb50e7afaa961d70e42459b2f726fb2eb2d60166f94e8736992f8628000bd4046b421bfe7c8a767da7686095cf184e42bb2fdcc3d05e3349ba12f52db26401581a74cfbae3d1503e6e09934ee84e9fdb63c6738f8a5016d412c722fe39f74da255863e17303a0bf7719954ce442235837091fbc8656da0b0abcd7497e6d926375df6c322ebb9bea6798f9d5270a61c4a17cd9fd1e22daa4bfa79f2960106074d2adf9b1862d30c914290dfc9e2ab3e8509e1ece12f032fa03e93d3700b97ed5d04eee5cc291a2c3962aa8f51634d7ed89b35b7d499019b670515aae03a6597e79e7b53f360d53813d4535fc6299b5c0fadbfc1478dd15339a77fbc16b0402a57a85fa28f06a4f111331410c6b428f93d188b6ed22dc160e476da9fe90e6a65ab63fb8781e8dff607e63cf2e443ad06c23a34c1c3c7eeceb031214850b8b4d921437cfa38c0316196af4fa2bbe994def604825ac23445ffa56c63b498ea6add4c83be61317e6bed5c44c9fdd08309377aab8b3daf4258db51981054c869d2855d041f69eb21ff1eb97342ba9996d861a58842b25d5ce18ba47cf09e4a2d9a56339e67e64588d6fff1c01971373e64a661b7dc5031e5c88c12edcc72a6cfe9fdbb8cce0e902e49935659ceb6daf22b91f7b27f0e88ef2d1640db3d7bc4f82bbbe70c2d457cce23524f45ecd22488b9df3bb16d2f7303ed58e3cf4390690f00df63e23302f82064097afe2477e654d9c3d392b8a35ea8c8e2b3ac5a9608a86cd29fcd7489a93ddaa5bed7ac88ffe8cb21296e94b41a2aac7d5147ead9972d31cd7c8ae9776a895b68d911983bd0335bfdb511183dce43527e1597d909d2f25d190a7d199713acc59a88264cea3a7f5bc11dfd6483e1d2f0ff3cab671893daf2869ffcaf86c6d8f306e5aebd712de391a94a6ff2ff9d22f54c0d1663fea48db15c562ec6e5fb56838b7bf2e98aa874d1d6987e63b916fc92fe3dfd643d49e63f2768350ab23c85c682e451cc44ebe5e9f27361b7c5cab9a4cf77752e35e31ecfb4d73241fa3deed5e52c53d97980c13839145024d6f1d9d56dbce05b7450bfa157b264c48c3a4c60e7274787406fabcdb1d2752b5ab199ddc1a2ebb2a69cc52e2edf2435bed8e8d83c1ce0f28fe3b515ef6c024e493b5d316049d285f7bbbdfd9ba4723cdd2955d45af2a18f19d6f487029040500c6834e9ce459b81bf0a8b010f7ab7822c703f75d9e395df90b1ce6dde123119747b443058fd70bbda38eb5340c7ba6151c015f7908012fd06a29b9ba7758296c3d5eae89c449b559fb26fbf7e3f5f1a048696bd0c5a88daf197b5e425342c853d2f08165ef44a8315ed88be965e66fac56cde880090cc2c7574bdc690407b9f041da8788f32bec21f6aba82156ac4dd8f85c7448d60477edbc5d3911d289600ec0e73e521cc6b00247f07360faba9710b98765d336e8cbc0caa2d5c5e35c3bfe3a8c5bc52411946f92a6f457ba09eb78dc8a225318638a8091f0ff4745b37f2a814ebaaa7868696413b51c51402ec5201c7778737895b785789fc937ea8419199f2844475b6edb01498b3b65a4b6800cca24058641f8ee1fd09e4a8d4c3c15f94639412562a30698f7f371db99b0de991e4e7a886fcb83b4116cf20093881d5a60e46ef00eca53fe79b06d5b4514fc795bd1144f8f955471dcf291e1493a16373e9df5dec50f0b82780ddbf59bd28ed9cda1c6158345e99b3eab19c5b1635162104a80b4e1f0d53cd540fddfc9db69a4790442bfeeb71a51e510630afedd97b0af62eea8058b22946c7e0791fb78b8c5c0ff5b60a35860aa1942639ced516b738d9157278332bc05eccf8b6cc4e0a86482bc13d9665380685c0e1ab04f7d6f914ada85e696db163f38707ca959a45bf1a83e6b7fe151fc495138a1e6e63f59038619303a7dabe2d2acd5ec022e1d4edd35afd7b35f6644ff6dddd0e32fe7eb9411d121c6c87c10d2121c8922dc1608b3670012d0624a120f7761c5f6ebdab723c4c882e2a245a85fd71c9f9ca6f72ec6bff338b6f8eb25b102208d1b153a570f6029f6509c9b592cd18cf36f8f07bf7ff1c8c8912415cb1a905e462e42d12fb679ad4543a4a60a224176b6875e8c1fe850c2071245b82a1db04fce91f902c0ce617c86965c434b18785f995c40e4816472b68d69593a9e3cb27ea72e1e25e0ef0453d160244985ef3fe9d0357b1d860e32e41f926b2f518d24dd1e953a7e5a7c040e26d78a36d5c83001d7fb83bcc5f4947a640da89b28e6fbe76011a6efc93c8486ca598223428a274165deb2b1f3deb80611f9129eaa1135a5ea87027ff05ef5f1308e1d99edfba21fc9e38c289b80f4addff3e29992fe32c34c929788683f300d8f8d4f8ecabfb0c5da0e100b5683ce9b4a64f44b2fa4c5ac4772097815007068cfa26ab87a477adfae6d19126f0f74e3dfd338974ef9ca27eb3047995bf8e1cf297e2dde11cbc740731b0bceb274f79ee426ed155722f4622243fc64bbd49ac620d56b02b198fc89b2414223938cd6777fe8ccceb6b5d1e1fb384a3bcd3188bb994c253de333f69f769489a0ef3d9a1b99c41a0b558f4199d30fd65ef67c9fe990dac5c8a08daedb3c863e372ef7bee9581c295e1dc82c3e317a8a0c6fa27b335bb127967894474f11e2283a663751b70c2650149a57a169088ab5dc8d71e32207d2f1ad64485f18b231d14add12d64b540a9001edc654ae39072329520af808917f4d52a40a293bc3e74f9a959c6414a3e9250baabe74bfb3bb686b852a88c92074d58ef1a304ab9cc7c8668ebd6c43d51ac1d7cb8c12c1bb11a830dd58c163d0f481e053a3a09049ac91b3d34c4a6f1fd8a2203caa489f310419169768adb0db1d3a1b1e0ebd55fee138db13abb6d11769e054de62c364c72d168f58e71c40490dc84b76dc5df91f69565b5989919e21090f22d8d49f585ffa44f6e5c9cabd06880f293be366260445ffb74e93e6178c91fb13e5a07b47868fa3833aa4234ce2bf6ecf8297a6f266eaa54628a3a4bb8274d505e3cb4f73e69935a3689ecef000d2517129adb7ac54897f6a1c0b98aab12bf1e446bc0f0cb6da6e89e579bffc6f2e71057a5d5ea7de19cc7c680b1752bdab3d20384da58c7bcd0ed7ac6f52b6fe4178818f9deae0bbee8b5971d20003302268760ae4119ed1e2b3aa64123c4e95b72443ea3702b2479c8533592d060e5da0145b0f8330bd9ad38b4b23200e67c3e808b7c4023df120d5dd8f87220243c2739847d9935fc4ad913d1722fe4d2efb83000ed5eef6bac0c0ee41dd2d006d58ed4afa2ac537ec5c94a083145878a2fbc522edc64442246cb826673a974726fa7b34d8d9b9d842cc89fdd5c162be76f72a7b517b63e8fd38b3454eb9683be8d3e757efa0af610afa26af30338bb3e3b390be1e6512b60324952bcbed690e3ed7e13238446c504d650e42d4a6ecc9382cc9c0021528ab561e1cbb2890491b5d9da703c322681c53b03f154d232e6862a354fbb26418ff151a99b9312ce7ba3a95fb05eda85580c2e5ef0aab02fef5cbf58ac6f64eea56f2b2af1407d08b69fc99556b287001fc5bbef01810275e1109e67bb76c9f05323b82652bbcf5e5beb8cbed293c3e2e8e97f46492d7b7ef25f651c128b81fd15c54113f1341bd19b223f391c6991f511c1eb6dda8fac57de07fc2e1af3b35c3e844aa6c86af7ac79ade5344c99db008b41dc3651e4ce14d449efb159f0517b25ca9dc2716d19a2d475e5015cf1028a108c4341d2ebc20d9ade1f37d041f1059e51b78cfbb7f2043c6d310c2096d19a0944b4ace05ee9220e6cb1a7924c16d4fa1b9677ba88a0fbb071c03654fdcfe5faaf37df113399ed9c3a5087f182a26b0fb1de3ff9395af80ff7eac3dd2d01b92df89dcc841fa427e50ef052db587ea487282c01a34cad878e93dbaa6caae6c34e21dfabd9ac43c5ac7d9dab94177bcfcd62b24b71b1c0609c4a9c96a71135eaf0076cf17b8f1d27c5de688568edf2388dfc844a42523ba099f38032fae9fb67dfc3442f971787c9a22250bbc2c16542a7414fb8db3a0a80d937c926022c9832e64ca5718c7a3b4117022cc13a739c495fe1e1eab672b543146237d00bd47957e51db799a8eab9ad563ba4a054f97f6070bc8175a3396ac69751862a051f693f979846f4822055de47fd021bea7d28fcc02dccd28b882361f16190ff7c6a34ea678f21dff66a44a19dd89bcc5df54f2f47de6ef6dad9bbf8c7c3d7a32b21adc1bad4b1871b43c443a65cef27ea3a4080944141505b2de709765bb40577ef50ac7810e699306961517f695cbbcd40a5e125386c4b5ae3d057ccf9fcabb63f9509fb0aa43c825a62330937e133ad2c69b8f23a0eba75a0b99f07b3122dfe8188a2d90d79fb623fb832e33ead41d93ee2889e471f13a83b936a47a7bef05d608175c795d67f328392199383462581109956dc18546129ee3f5d7bca051405e273f95aa64caa9c62ea54a1e1d0f9e3268862cbd6c575efff3feb68ee75b772cc6f24feef908c31544c28a9606000129dac6361c92e4792c6a79ad3de141bd86d7c5ed8892fbef507a72cf33d2c201f3872d17058688f7bb39ce608d4667df9830c9faf5b6b66cfe93836a7fe40a30dc4ed86f76aae20485227bfb6cd862e63fdaeb4aea8b6039d3fb307d3f0bf97d9299f44d7d5b6da30ee6d6dda9223ea64235705e4cc2e4e9fdb5aadc9b307c73e8f369bcc2da7989992683a7f8932a332015cc36e1733234b449431addf724b0478dfa0d1430ea2738abe2d4f2dc5c6ed829c03d43754a72eeb79c15d103c69a7d2bfa4197e0f4528325fed2add5cec78c5d788dc1994be8e938d8a5e71d20d5f9d724032fdb606f563ef5ef8675a33d14d33ce849dd52a814b1605aea140368150b00dbeabaf43da6c2efdda18d6db54fcada5874db8f8e0875eb9ea3c85b9baca70a75b1ba70518693e6e2e607b39a002f5563b85ec827d5372b5eafc296e5156bc748962451d05ba4a2b4261ec57f7cef69a1999b83439a3d2f5c3144a0a5f3f4efe846bd914df159150eb7119248bf1528794471f993179365b565099fed5ad0f82ff9b74fb99a6cfd0d6a072781e5bf45b536bbedd4b0bbbafb433a430cf692ead0343d88ce9588a6d3131f74b0bf8d0a2f6ef8a0b07a3f76c851d5939e52191d2aa60cac237f9f35447dbb3f580dba9ecbe18a8db03d92ccabfeed7466cbe68f62b0987a807e6b9955c2d296ca3855014322b41d08e34c6c80484050591213dee7cf705d73cf76897b0b5e4a3fc0b010813aa1169601595021b6c4a0882ef5307c60f266f5c008ce2e89f3493170408f5afb4a64158518fd32398113a9daec4cd97d29802b4d05036c32471dea52317bf00bb3c1b978c65e811289790d12516078d12e4cb03484eb7d45ba96af341467156482594f2c4785ea11e6a2b42308c62da3fa316cca15350ea9e760e72d5dd6f294f94c7575864f2985583a432886d39edca716439ca9553f5f935d8a3174e60bd04f738f2040163568c1f28a7bf116e7742ce6f36443da6197f47b40f12a3cb105dd00fe43b9400d92c17cbce78ba16d94041a150d94327eb52d9be0403366e5e5b8f5828aab16018208d7d22fcbdfb54772b1650588c2825c82e809a5442fadeade55b919758000a9dd9054337a14460c6e3eddd29cdfa23ac4f639f397770981fb9c84910d7ae2289d7c39d2ae460e0ee7ac5105e3a201574eea6dbc6b8a36a6cc62f7ce254c2fa37b5f2752ce67bad0fd4659adc927147a48671c2c78211457d2d343a4fbd852072b2f919a51d1125dc5cf1c69bbf09a5b6d31023544112886628b007245768c19d65b36b4a0720835a12a9d2114de84549c9cf6f64fadd6ccc6184c8107b8e573cbf252ea6183c750a8781a4b7676f716896e6baf47513e9148b605e636ab658ef2e548257c2ebc61a698ef803678adfc8dabf910de2a0420b4f7ec66b408d9ea637d85285661f41010dc54ec46f648f3c7b33576a824e476399ff896318e64d9f7950526a033f38c9e63d65a532aa627be569d155c00be865b1e71c44af801f7e2e0f7a0e0565dc2592730e9f5bd84d7cd939ea28939a41a3bb51a3d33253474ddedf7f781bcd6a4b40a6557ff98775a652901e818d47c751919b9c7534d6f5bc4c892d5fc1c01a7b663f5097911043e7445d48c0cdb5a04ecd778551c1dbab1918bd176f61b516bf61484e66d6764de926408d8dc56542654f4adb5ffa36a3491644dd7dee0a924bf0ff4a91ead982f74a7abfe19b4a08683050872eef7574d9b660f8d890729f08fee2a189f5567a6403f8c9a3b802e68393b4bd2cfabfe2522ba1ff428714b5999d17aab4476509b8659c60a427ae2ea1d7dbfb5249fd2fc7b7da4894e6bc63d91d6dc112040835df5f9d7dc9e76eea19108e7ab89b7e7e99e71fe1cd7303e84c03a63c48e17750d27124213869e84a6b57a52ddd9606f50c883915dd5440918f5ea50114e6235d08d18aa6a5aa68ce9cf58e2785cd99f622b45abf0bc3d60a1f6c6d4ad76300051d95a5b08fbb408da3182e5920521f05d52694873b88a174b5af3e0b21c48fc228ac896e558fc846e08f707f3d5caafb6db690b4b348d3a35b63452e83731ae47ffc3e35966ee4d1152f11a459b280e6fcd9ab00cb751b4a8196a3a8c813caa2708398338d9f22f52c349874ce61c6ebd8f4251271d9b8c87e3e7f2fe2dcbd0c4927214e4f8016c3f0eecb53373aff56f54e291430acf713076b6b7495ff29fc655dfe14e8a154397ed0349cff3a6b770eed8a9a37a14549d37cc1a9d99a4a0c5c25ecfe3aa224386c1d959af69a65d1c3d8c4c73610bfc53e63479d799dddf7f98223d7c4ea3a1a729dd1d38774874f48b55dd6311f032c89ab593272b2ec76ee28ef002ae40cee0429cbd6395c499aed2709aa5ef401f63688fe10403a18e610efa7d1d1cb751f047c613d2598e4e243d0a18eb391cbd19e710eaaa98b5b49c80b97e354e0592ec452dca687e6f5ce208ce70b58177bc163cdc9d83eb7fad6beb4031c507af9f6bb808e61670afc8ed6bc6eb1ba8a855ff98cbd3084a9b96858584699959800b5cbda3f3857a9d3316bc3d92fbf054b9604b0573f22f070a9f9ca8a1b8379c10f18fc2e69a5dcc91df32c229a0f7c61fb9934ab162d668c2b49ff1fb9e40d041cad7bfa7dcb175ac0d1dc74fa185321c243125460ac38273b9491f96d9dd6c28668cd41c262feb518377e40511601c49e056d0837add761a91e300588a4b951b4e94948c9935bc8a788950b69a3f6b03e3efe132126ebf980a5691b51e450084bde1469077c9d5580efd221ba3dee9aea463300a95447330759949be52512334ea4ae2e0e2d0d135038886ea3732c5db0a9863a17050744b6977a85f2a4c805f4be5ba2d35e7ce8fe2792bf8fd010061a72d9b0b4feada3f30518c46900587e25c60f7c6c8b86dc29ba1b573130c7763db82b74ad39dad67e187a6cb155b9f4f7d2e4cd6863547ec0862652380c0fe26eb274d3147d975aff8c2267e425813a6f7953e814a096551f5d78c16e4b101c2ba5e5c092a1000f5c6f3b10c4b15e496f401d00da7eb298b6bd08623f7f564dd4dff6fa52d7f1eb604bc9202d49f23bd43d2842cfea03f54803a53dcfc29ba52d36d608aa882e3dee9b5ecae2adfac62f550b462c993ed8cddc4744059eff4cdd1c0ef03cf67a48534c4ba4b374df16253c2bba2b52c9b72b1d54615ef0104beb80e206f491fb8f25415e755bfd93ca38e60d4bf4d65e5631560f4492c45244d521f61f187c9010cd057a78fe776fd0eece8dd26035707c3e67b23a872f7b67aec40e598d8f11aa4a54f2bbbcccdabac2107c1f898d16c45f0766d822ff2c848eb28fcedf55500ca7f044043391b923f651006195111dd2676088b4a82b049c2b0279dac7a2363dbda52ce2b76517c8f24013861dcb61c834f4e328dfb5094c41b0f3a074c860b1e46c862cb08af3d130b5d6efb631869afa31cfa91a1e0b76c472ad39a12ccdf1eed3185912bd6bab294aa317d26d92bf6a5b142d495d6049f4429e5cd60585c65647332346f9cefbc7c3a4c0c3e5d2de4c2a4aeb6d0e6305c2ce6b313aa40774759ff8187c17fea5ac5181ddea2f290954ac3d262910d38d3c70cf2a0f0155f95bf621f15c3a4884235f05f6906243b66e2b62694105387c946782b281691e2e11cd8aff6c892273f765b9c34fa344309cbd2cca3eb9c40b52d08c371d527b344d871f8ecf2fb203e0a9767ae2bd7d8ea45b4272cfa410f1e60738af5473642cf750bf73e9a6625332c654b569f3bc8bd81a4087921db93ee73bdcf6b238817e71ddf917d76630880ea3357e9c09fe1df2544539736a9525d0974aa077a7a92ec5704d61097c3c4c78c28e4f3d891130df570718b170a881e2ab7f126ddb570e29dd174dfe1c993004bd8ba69b5403204d6038d23c21373ea0b60329158c97668000be19a7e0282e7167da24330928b9b3b10a5993ed40a8e49995ecf0eac278fa53f09a9642d708d9bcd2c286bfda56cef91ec833351a45ed21d9f754c6a09d59b43eab5e1030d3454096caa0c93fb692090d2ca40de6a8f39c39a7e27e6713529d12dfedbd63e905f92551f96e8bc73550d1621bebb98a4802ee59464496d98b8a82258626f63bbc602c064876a6cc2456151cee842dd0fd57e1e4c0702d22637df6209e02fa656586e00dc721bdbaa2ca326a7f7ee8e6c50833b8ac04bb536db687c2513066235426fe208ce67ef9979bdf724f03485de7c3b3a387dafc2b4052d7bb4c55f5cfa3e058ca6c2471c5a13737625ad19ee95c31ce6acdbb2103425e01bd3de0ac4b5e3ad1c8eb84d4ce8cf1d66b9d99ba40a3ea0dc925a635abec513781eef162705aa7ffd203317f1efa1c5954fcc2d8687cb2a36a4d18e93350cec34d0a30ac4910fa616ca080c01dae1a212d0d84090df201e5b98bc5ec1a3a6da2c67009cdb2f7acb44c98654cdd928de93555f61ca0b38766672b186e398e82d9724fcb3a9a87a9800d0724c2519bb146b")
	if err != nil {
		return nil, err
	}
	// generate fake file block
	for i := 0; i < len(fileBlock); i++ {
		copy(fileBlock[i][:], fake)
		if err != nil {
			return nil, err
		}
	}
	return fileBlock, err
}

type Challenge struct {
	Index []int
	Nus   []*big.Int
}

type Auditor struct {
	PBParams  *PublicParams
	Challenge *Challenge
}

func NewAuditor(pbParams *PublicParams) *Auditor {
	return &Auditor{
		PBParams: pbParams,
	}
}

func (this *Auditor) GenChallenge(challengeSize int) (*Challenge, error) {
	//set index
	//TODO set random index
	index := make([]int, challengeSize)
	for i, _ := range index {
		index[i] = i
	}

	//set nu
	nus := make([]*big.Int, challengeSize)
	for i, _ := range nus {
		nu, _ := new(big.Int).SetString("e37716c842b079e0ff3ec5a5ce53d93dba781dc5673221d6897bf3c58317b04c6f1e4f6ea19158ca4accab70f644f459e879887a0ddd943ed6e8ce39374267ffff2cbc2ed8657bcd0dd20629f535679c", 16)
		nus[i] = nu
	}

	return &Challenge{
		Index: index,
		Nus:   nus,
	}, nil
}

func (this *Auditor) VerifyProof(proof *Proof) (bool, error) {
	R := proof.R
	gamma, err := this.PBParams.HashGTToInt(R)
	if err != nil {
		return false, nil
	}
	Sigma := proof.Sigma
	g := this.PBParams.G
	// leftPart = R * e(Sigma^gamma, g)
	leftPart := new(bn256.GT).Add(R, bn256.Pair(new(bn256.G1).ScalarMult(Sigma, gamma), g))

	index := this.Challenge.Index
	nus := this.Challenge.Nus
	// sum = IIH(Wi)^vi
	sum := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i, v := range index {
		name := this.PBParams.Name.Bytes()
		var wiB bytes.Buffer
		_, err := wiB.Write(name)
		if err != nil {
			return false, err
		}
		_, err = wiB.Write(big.NewInt(int64(v)).Bytes())
		if err != nil {
			return false, err
		}
		wi := new(big.Int).SetBytes(wiB.Bytes())

		nu := nus[i]
		hv, err := this.PBParams.HashIntToG1(wi)
		if err != nil {
			return false, err
		}
		tmp := new(bn256.G1).ScalarMult(hv, nu)
		sum.Add(sum, tmp)
	}
	// tmp1 = sum^gamma * u^mu
	tmp1 := new(bn256.G1).Add(new(bn256.G1).ScalarMult(sum, gamma), new(bn256.G1).ScalarMult(this.PBParams.U, proof.Mu))
	// tmp2 = e(tmp1,v)
	tmp2 := bn256.Pair(tmp1, this.PBParams.V)
	// tmp3 = e(g1,g)^zeta
	zeta := proof.Zeta
	tmp3 := new(bn256.GT).ScalarMult(bn256.Pair(this.PBParams.G1, this.PBParams.G), zeta)
	// rightPart = tmp2*tmp3
	rightPart := new(bn256.GT).Add(tmp2, tmp3)

	leftPartBytes := leftPart.Marshal()
	rightPartBytes := rightPart.Marshal()

	return bytes.Equal(leftPartBytes, rightPartBytes), nil
}

type Prover struct {
	PBParams   *PublicParams
	FileBlocks [][BLOCK_SIZE]byte
	Sigmas     []*bn256.G1
}

type Proof struct {
	Mu    *big.Int
	Sigma *bn256.G1
	R     *bn256.GT
	Zeta  *big.Int
}

func NewProver(pbParams *PublicParams, fbs [][BLOCK_SIZE]byte, sigmas []*bn256.G1) *Prover {
	return &Prover{
		PBParams:   pbParams,
		FileBlocks: fbs,
		Sigmas:     sigmas,
	}
}

func (this *Prover) GenProof(challenge *Challenge) (*Proof, error) {
	// generate rm, rsigma, rho
	rm, err := rand.Int(rand.Reader, this.PBParams.P)
	if err != nil {
		return nil, err
	}

	rsigma, err := rand.Int(rand.Reader, this.PBParams.P)
	if err != nil {
		return nil, err
	}

	rho, err := rand.Int(rand.Reader, this.PBParams.P)
	if err != nil {
		return nil, err
	}

	g1 := this.PBParams.G1
	g := this.PBParams.G
	// RLeft = e(g1,g)^rsigma
	RLeft := new(bn256.GT).ScalarMult(bn256.Pair(g1, g), rsigma)
	// RRIGHT = e(u,v)^rm
	RRight := new(bn256.GT).ScalarMult(this.PBParams.EUV, rm)
	R := new(bn256.GT).Add(RLeft, RRight)

	// gamma = h(R)
	gamma, err := this.PBParams.HashGTToInt(R)
	if err != nil {
		return nil, err
	}

	// set mu
	// _mu = Sigma(vi*mi)
	_mu := big.NewInt(0)
	for i, v := range challenge.Index {
		nu := challenge.Nus[i]
		m := this.FileBlocks[v]
		// _mu += v*m
		_mu.Add(_mu, new(big.Int).Mul(nu, new(big.Int).SetBytes(m[:])))
		_mu.Mod(_mu, this.PBParams.P)
	}
	// mu = rm + gamma*_mu
	mu := new(big.Int).Add(rm, new(big.Int).Mul(gamma, _mu)) //mu = _mu + r*h(R)
	mu.Mod(mu, this.PBParams.P)

	// set sigma
	// sigma = II(sigmai^vi)
	sigma := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i, v := range challenge.Index {
		nu := challenge.Nus[i]
		sig := this.Sigmas[v]
		subSig := new(bn256.G1).ScalarMult(sig, nu)
		sigma.Add(sigma, subSig)
	}
	// Sigma = sigma* g1^rho
	Sigma := new(bn256.G1).Add(sigma, new(bn256.G1).ScalarMult(this.PBParams.G1, rho))
	// zeta = rsigma + gamma* rho
	zeta := new(big.Int).Add(rsigma, new(big.Int).Mul(gamma, rho))
	zeta.Mod(zeta, this.PBParams.P)

	return &Proof{
		Mu:    mu,
		Sigma: Sigma,
		R:     R,
		Zeta:  zeta,
	}, nil
}

func init() {
	// set log flag
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)
	// --------------------------------------------------------
	// Initialize params
	// --------------------------------------------------------
	log.Println("Initialize public params")
	_p,_ := new(big.Int).SetString("65000549695646603732796438742359905742570406053903786389881062969044166799969",10)
	// set q
	_q,_ :=new(big.Int).SetString("12250973345822939225017817058394006454275419240816619717313843311479494517986894178997854796661650665294130746028827960605444651717210785557944282627749331",10)
	var challengeSize int = 2 // challenge size
	var blockNum int = 4 //  block number


	// --------------------------------------------------------
	// Setup Phase
	// --------------------------------------------------------

	user,err:= NewUser(_q)
	if err!=nil {
		panic(err)
	}

	publicParams,err:= user.GenPublicParameter(_q,_p)
	if err!=nil {
		panic(err)
	}
	publicParams.InitHashFuncParams()

	user.PBParams = publicParams

	// generate fake file block
	fileBlock,err:= genFileBlock(blockNum)
	if err!=nil {
		panic(err)
	}

	// generate sigma
	sigmas,err:= user.GenSigma(fileBlock)
	if err!=nil {
		panic(err)
	}
	user.Sigmas = sigmas

	// --------------------------------------------------------
	// audit challenge phase
	// --------------------------------------------------------
	auditor = NewAuditor(publicParams)
	challenge,err:= auditor.GenChallenge(challengeSize)
	if err!=nil {
		panic(err)
	}
	auditor.Challenge = challenge
}

// self-defined audit function
type verifyProof struct{}
var auditor *Auditor

func (c *verifyProof) RequiredGas(input []byte) uint64 {
	return 1
}

func getTrue() []byte{
	result := make([]byte, 32)
	result[31] = byte(1)
	return result
}

func getFalse() []byte {
	result := make([]byte, 32)
	return result
}

func (c *verifyProof) Run(input []byte) ([]byte, error) {
	log.Println("input length:", len(input))
	log.Println("data length",new(big.Int).SetBytes(getData(input,0,32)).Uint64())
	zeta := new(big.Int).SetBytes(getData(input, 32, 32))
	mu := new(big.Int).SetBytes(getData(input, 64, 32))
	Sigma,ok := new(bn256.G1).Unmarshal(getData(input, 96, 64))
	if !ok {
		log.Println("can not unmarshal sigma")
		return nil, errors.New("can not unmarshal sigma")
	}
	R,ok:= new(bn256.GT).Unmarshal(getData(input,160,384))
	if !ok {
		log.Println("can not unmarshal sigma")
		return nil, errors.New("can not unmarshal sigma")
	}
	proof:=&Proof{
		Zeta:zeta,
		Mu:mu,
		Sigma:Sigma,
		R:R,
	}
	result,err:=auditor.VerifyProof(proof)
	if err!=nil {
		return getFalse(),nil
	}
	if result {
		return getTrue(),nil
	} else {
		return getFalse(),nil
	}
}
