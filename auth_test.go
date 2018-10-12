package main

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func genValidTokenWithExp(exp time.Time) string {
	key := []byte("secret")
	claims := &jwt.StandardClaims{
		ExpiresAt: exp.Unix(),
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}

	return ss
}

var _ = Describe("auth", func() {
	Describe("isTokenExpired", func() {
		It("returns true when it's expired", func() {
			token := genValidTokenWithExp(time.Now().Truncate(time.Minute * 1))

			Expect(true).To(Equal(IsTokenExpired(token)))
		})

		It("returns false when it's not expired", func() {
			token := genValidTokenWithExp(time.Now().Add(time.Minute * 1))

			Expect(false).To(Equal(IsTokenExpired(token)))
		})
	})
})
