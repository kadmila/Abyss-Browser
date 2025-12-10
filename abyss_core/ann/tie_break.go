package ann

import (
	"bytes"
	"crypto/sha3"

	"github.com/btcsuite/btcutil/base58"
)

func TieBreak(id_A string, id_B string) (string, error) {
	A_bytes := base58.Decode(id_A[2:])
	B_bytes := base58.Decode(id_B[2:])

	var low_bytes []byte
	var low_id string
	var high_bytes []byte
	var high_id string
	if bytes.Compare(A_bytes, B_bytes) < 0 {
		low_bytes = A_bytes
		low_id = id_A
		high_bytes = B_bytes
		high_id = id_B
	} else {
		low_bytes = B_bytes
		low_id = id_B
		high_bytes = A_bytes
		high_id = id_A
	}

	hasher := sha3.New256()
	if _, err := hasher.Write(low_bytes); err != nil {
		return "", err
	}
	if _, err := hasher.Write(high_bytes); err != nil {
		return "", err
	}
	hashsum := hasher.Sum(nil)

	// reduce hashsum to 1 bit
	var x byte = 0
	for _, v := range hashsum {
		x ^= v
	}
	x ^= x >> 4
	x ^= x >> 2
	x ^= x >> 1
	x = x & 1
	// x is 0 or 1

	if x == 0 {
		return low_id, nil
	} else {
		return high_id, nil
	}
}
