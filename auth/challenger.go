package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type Challenge struct {
	Code     string
	Verifier string
	Method   string
}

type Challenger func() Challenge

func DefaultChallengeGenerator() Challenge {
	return generateChallenge(32)
}

// generateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
func generateRandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
}

func generateChallenge(length int) Challenge {
	c := Challenge{}

	c.Verifier = generateRandomString(length)

	csum := sha256.Sum256([]byte(c.Verifier))
	c.Code = base64.RawURLEncoding.EncodeToString(csum[:])
	c.Method = "S256"

	return c
}
