package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	merkletree "github.com/iden3/go-merkletree-sql"
)

func main() {

	// BabyJubJub key
	babyJubjubPrivKey := babyjub.NewRandPrivKey()

	// claim Expiration date 
	t := time.Date(2361, 3, 22, 0, 44, 48, 0, time.UTC)

	// schema initialization from hash
	countryCodeSchema, _ := core.NewSchemaHashFromHex("9b6c3ea3f301a241d9679af6aedccba9")

	// Claim Data
	countryCode := big.NewInt(84)

	// Revocation Nonce
	revocationNonce := uint64(1909830690)

	// Issuers DID
	subjectId, _ := core.IDFromString("113TCVw5KMeMp99Qdvub9Mssfz7krL9jWNvbdB7Fd2")

	// create claim
	claim, _ := core.NewClaim(countryCodeSchema, core.WithExpirationDate(t), core.WithRevocationNonce(revocationNonce), core.WithIndexID(subjectId), core.WithIndexDataInts(countryCode, nil))

	// transform claim to json and print
	claimToMarshal, _ := json.Marshal(claim)

	fmt.Println(string(claimToMarshal))


	// Issue claim via signature
	claimIndex, claimValue := claim.RawSlots()
	indexHash, _ := poseidon.Hash(core.ElemBytesToInts(claimIndex[:]))
	valueHash, _ := poseidon.Hash(core.ElemBytesToInts(claimValue[:]))

	// Poseidon Hash the indexHash and the valueHash together to get the claimHash
	claimHash, _ := merkletree.HashElems(indexHash, valueHash)

	// Sign the claimHash with the private key of the issuer
	claimSignature := babyJubjubPrivKey.SignPoseidon(claimHash.BigInt())

	fmt.Println("Claim Signature:", claimSignature)
}
