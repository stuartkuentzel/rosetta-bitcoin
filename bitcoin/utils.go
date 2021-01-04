// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bitcoin

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/coinbase/rosetta-sdk-go/types"
)

// ParseCoinIdentifier returns the corresponding hash and index associated
// with a *types.CoinIdentifier.
func ParseCoinIdentifier(coinIdentifier *types.CoinIdentifier) (*chainhash.Hash, uint32, error) {
	utxoSpent := strings.Split(coinIdentifier.Identifier, ":")

	outpointHash := utxoSpent[0]
	if len(outpointHash) != TransactionHashLength {
		return nil, 0, fmt.Errorf("outpoint_hash %s is not length 64", outpointHash)
	}

	hash, err := chainhash.NewHashFromStr(outpointHash)
	if err != nil {
		return nil, 0, fmt.Errorf("%w unable to construct has from string %s", err, outpointHash)
	}

	outpointIndex, err := strconv.ParseUint(utxoSpent[1], 10, 32)
	if err != nil {
		return nil, 0, fmt.Errorf("%w unable to parse outpoint_index", err)
	}

	return hash, uint32(outpointIndex), nil
}

// ParseSingleAddress extracts a single address from a pkscript or
// throws an error.
func ParseSingleAddress(
	chainParams *chaincfg.Params,
	script []byte,
) (txscript.ScriptClass, btcutil.Address, error) {
	class, addresses, nRequired, err := txscript.ExtractPkScriptAddrs(script, chainParams)
	if err != nil {
		return 0, nil, fmt.Errorf("%w unable to extract script addresses", err)
	}

	if nRequired != 1 {
		return 0, nil, fmt.Errorf("expecting 1 address, got %d", nRequired)
	}

	address := addresses[0]

	return class, address, nil
}

// DecodeTxOpReturns takes a transaction and checks all operation outputs for an OP RETURN
// if present, it decodes the value and updates the operation metadata
func DecodeTxOpReturns(transaction *types.Transaction) error {
	// Loop through operations
	for _, op := range transaction.Operations {

		// We only want to check outputs for OP_RETURNS
		if op.Type == OutputOpType {
			memo, err := ParseOpReturn(op)
			if err != nil {
				return fmt.Errorf("%w: error decoding Output ", err)
			}

			if len(memo) > 0 {
				var opMetadata OperationMetadata
				if err := types.UnmarshalMap(op.Metadata, &opMetadata); err != nil {
					return fmt.Errorf("%w: error unmarshalling metadata", err)
				}

				opMetadata.OpReturnMemo = memo
				md, err := types.MarshalMap(opMetadata)
				if err != nil {
					return fmt.Errorf("%w: error marshalling metadata", err)
				}
				op.Metadata = md
			}
		}
	}

	return nil
}

// DecodeOpReturn checks if an output is an OP RETURN and parses the memo
// func DecodeOpReturn(o Output) (string, error) {
func ParseOpReturn(o *types.Operation) (string, error) {
	if o.Type == OutputOpType {
		var opMetadata OperationMetadata
		if err := types.UnmarshalMap(o.Metadata, &opMetadata); err != nil {
			return "", fmt.Errorf("%w: unable to unmarshal output Metadata", err)
		}

		if strings.HasPrefix(opMetadata.ScriptPubKey.ASM, "OP_RETURN") {
			splitOpReturn := strings.Split(opMetadata.ScriptPubKey.ASM, " ")
			opReturn := splitOpReturn[1]
			decoded, err := hex.DecodeString(opReturn)
			if err != nil {
				return "", fmt.Errorf("%w failed to decode OP_RETURN string", err)
			}
			return string(decoded), nil
		}
	}

	return "", nil
}
