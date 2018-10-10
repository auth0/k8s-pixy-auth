package main_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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

	Describe("refreshTokenExchanging", func() {
		Describe("httpTokenExchanger", func() {
			It("calls the correct URL with correctly constructed data", func() {
				expectedRequest := `{"grant_type":"refresh_token","client_id":"abc","refresh_token":"token_yay"}
`
				expectedURLPath := "/oauth/token"

				var actualReq string
				var actualURLPath string
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					actualURLPath = r.URL.Path

					rb, err := ioutil.ReadAll(r.Body)
					defer r.Body.Close()
					if err != nil {
						panic(err)
					}
					actualReq = string(rb)

					w.Write([]byte(`{"id_token":"new_id_token_yay"}`))
				}))
				defer ts.Close()

				rteReq := RefreshTokenExchangeRequest{
					GrantType:    "refresh_token",
					ClientID:     "abc",
					RefreshToken: "token_yay",
				}

				he := HTTPTokenExchanger{}
				rteResp := he.ExchangeRefreshToken(fmt.Sprintf("%s/", ts.URL), rteReq)

				Expect(actualReq).To(Equal(expectedRequest))
				Expect(actualURLPath).To(Equal(expectedURLPath))
				Expect(rteResp.IDToken).To(Equal("new_id_token_yay"))
			})
		})
	})
})
