package main_test

import (
	"bytes"
	"testing"
	"time"

	. "github.com/auth0/auth0-k8s-client-go-exec-plugin"
	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAuth0ClientGoExecPlugin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth0ClientGoExecPlugin Suite")
}

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

var _ = Describe("Main", func() {
	Describe("Config", func() {
		Context("with valid yaml", func() {
			testYaml := `
clients:
  testing:
    idToken: testing_idToken
    refreshToken: testing_refreshToken
`
			buffer := bytes.NewBufferString(testYaml)
			config := NewConfig(buffer)

			It("gets tokens when present", func() {
				idToken, refreshToken := config.GetTokens("testing")

				Expect(idToken).To(Equal("testing_idToken"))
				Expect(refreshToken).To(Equal("testing_refreshToken"))
			})

			It("returns empty when no tokens are present for client", func() {
				idToken, refreshToken := config.GetTokens("not_present")

				Expect(idToken).To(BeEmpty())
				Expect(refreshToken).To(BeEmpty())
			})

			It("cache should overwrite old tokens", func() {
				updatedYaml := `clients:
  testing:
    idToken: newIdToken
    refreshToken: newRefreshToken
`
				config.CacheTokens("testing", "newIdToken", "newRefreshToken")

				Expect(buffer.String()).To(Equal(updatedYaml))
			})
		})

		Context("with invalid yaml", func() {
			It("should panic", func() {
				testYaml := `
clients:
  - testing:
    - testing_id: blah
`
				Expect(func() {
					_ = NewConfig(bytes.NewBufferString(testYaml))
				}).Should(Panic())
			})
		})
	})

	Describe("Jwt", func() {
		Describe("isTokenExpired", func() {
			Describe("valid JWT", func() {
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
	})
})
