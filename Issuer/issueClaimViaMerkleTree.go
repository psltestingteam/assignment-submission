package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	merkletree "github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
)

func main() {

	/**
		1. Create key pair
		2. Create auth claim
		3. Create 3 trees and genesis id
		4. Create proof that auth claim is not revoked
		5. Create claim to attest
		6. Add claim to merkle tree and sign
	*/











	/**
		STEP 1 - Create key pair
	*/

	// BabyJubJub key
	babyJubjubPrivKey := babyjub.NewRandPrivKey()
	babyJubjubPubKey := babyJubjubPrivKey.Public()










	/**
		STEP 2 - Create auth claim which will contain public key
	*/

	// Auth schema iniatilization - hash will always be the same
	authSchemaHash, _ := core.NewSchemaHashFromHex("ca938857241db9451ea329256b9c06e5")

	// Add revocation nonce.
	revNonce := uint64(1)

	authClaim, _ := core.NewClaim(authSchemaHash,
		core.WithIndexDataInts(babyJubjubPubKey.X, babyJubjubPubKey.Y),
		core.WithRevocationNonce(revNonce))

	authClaimToMarshal, _ := json.Marshal(authClaim)

	fmt.Println("authClaim: ", string(authClaimToMarshal),"\n")












	/**
		STEP 3 - Create 3 trees (claims, revocation and roots) and genesis id
	*/


	// Create 3 trees
	ctx := context.Background()
	clt, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	ret, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	rot, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)

	// Get the Index of the claim and the Value of the authClaim
	hIndex, hValue, _ := authClaim.HiHv()

	// add auth claim to claims tree with value hValue at index hIndex
	clt.Add(ctx, hIndex, hValue)

	state, _ := merkletree.HashElems(
		clt.Root().BigInt(),
		ret.Root().BigInt(),
		rot.Root().BigInt())

	// Get gensis identifier
	id, _ := core.IdGenesisFromIdenState(core.TypeDefault, state.BigInt())












	/**
		STEP 4 - Create your claim to attest
	*/

	// Generate Proof for authClaim at Genesis State
	authMTPProof, _, _ := clt.GenerateProof(ctx, hIndex, clt.Root())

	// Generate Non-Revocation proof for the authClaim
	authNonRevMTPProof, _, _ := ret.GenerateProof(ctx, new(big.Int).SetUint64(revNonce), ret.Root())

	// Snapshot of the Genesis State
	genesisTreeState := circuits.TreeState{
		State:          state,
		ClaimsRoot:     clt.Root(),
		RevocationRoot: ret.Root(),
		RootOfRoots:    rot.Root(),
	}
	
	// add the claims tree root at Genesis state to the Roots tree.
	rot.Add(ctx, clt.Root().BigInt(), big.NewInt(0))













	/**
		STEP 5 - Create your claim to attest
	*/


	// claim Expiration date 
	t := time.Date(2361, 3, 22, 0, 44, 48, 0, time.UTC)

	// schema initialization from hash
	countryCodeSchema, _ := core.NewSchemaHashFromHex("9b6c3ea3f301a241d9679af6aedccba9")

	// Claim Data
	countryCode := big.NewInt(84)

	// Revocation Nonce
	revocationNonce := uint64(2)

	// Issuers DID
	subjectId, _ := core.IDFromString("113TCVw5KMeMp99Qdvub9Mssfz7krL9jWNvbdB7Fd2")

	// create claim
	claim, _ := core.NewClaim(countryCodeSchema, core.WithExpirationDate(t), core.WithRevocationNonce(revocationNonce), core.WithIndexID(subjectId), core.WithIndexDataInts(countryCode, nil))

	// transform claim to json and print
	claimToMarshal, _ := json.Marshal(claim)

	fmt.Println("Claim: " ,string(claimToMarshal),"\n")


















	/**
		STEP 6 - Add claim to merkle tree and sign
	*/


	// Get hash Index and hash Value of the new claim
	hi, hv, _ := claim.HiHv()

	// Add claim to the Claims tree
	clt.Add(ctx, hi, hv)

	// Fetch the new Identity State
	newState, _ := merkletree.HashElems(
		clt.Root().BigInt(),
		ret.Root().BigInt(),
		rot.Root().BigInt())

	// Sign a message (hash of the genesis state + the new state) using your private key
	hashOldAndNewStates, _ := poseidon.Hash([]*big.Int{state.BigInt(), newState.BigInt()})

	signature := babyJubjubPrivKey.SignPoseidon(hashOldAndNewStates)

	// Generate state transition inputs
	stateTransitionInputs := circuits.StateTransitionInputs{
		ID:                id,
		OldTreeState:      genesisTreeState,
		NewState:          newState,
		IsOldStateGenesis: true,
		AuthClaim: circuits.Claim{
			Claim: authClaim,
			Proof: authMTPProof,
			NonRevProof: &circuits.ClaimNonRevStatus{
				Proof: authNonRevMTPProof,
			},
		},
		Signature: signature,
	}

	// Perform marshalling of the state transition inputs
	inputBytes, _ := stateTransitionInputs.InputsMarshal()

	fmt.Println("final state to send to holder: ", string(inputBytes))


}
