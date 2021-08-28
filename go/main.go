package main

import (
	"crypto/sha1"
	"io"
)

const (
	sha1BlockSizeBytes  = 64
	sha1ResultSizeBytes = 20
)

func prepareKey(key string) []byte {
	if len(key) > sha1BlockSizeBytes {
		h := sha1.New()
		io.WriteString(h, key)
		return h.Sum(nil)
	} else if len(key) == sha1BlockSizeBytes {
		return []byte(key)
	} else {
		result := []byte(key)
		for len(result) < sha1BlockSizeBytes {
			result = append(result, 0)
		}
		return result
	}
}

func pad(processedKey []byte, padding byte) []byte {
	var result []byte
	for _, b := range processedKey {
		b2 := b ^ padding
		result = append(result, b2)
	}
	return result
}

func hmacSha1(key, message string) []byte {
	k := prepareKey(key)
	outerKeyPad := pad(k, 0x5c)
	innerKeyPad := pad(k, 0x36)

	h := sha1.New()
	h.Write(innerKeyPad)
	h.Write([]byte(message))
	innerHashed := h.Sum(nil)

	h2 := sha1.New()
	h2.Write(outerKeyPad)
	h2.Write(innerHashed)
	return h2.Sum(nil)
}

func main() {}
