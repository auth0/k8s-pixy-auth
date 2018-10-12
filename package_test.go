package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

func TestAuth0ClientGoExecPlugin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "auth0-kubectl-auth Suite")
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

type mockedHTTPTokenExchanger struct {
	mock.Mock
}

func (m *mockedHTTPTokenExchanger) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	args := m.Called(url, contentType, body)
	return args.Get(0).(*http.Response), args.Error(1)
}

type mockedPkceHelper struct {
	mockedHTTPTokenExchanger
}

func (m *mockedPkceHelper) InitCallbackListener(port int) (chan string, string) {
	args := m.Called(port)
	return args.Get(0).(chan string), args.String(1)
}

func (m *mockedPkceHelper) OpenURL(url string) {
	m.Called(url)
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

	Describe("pkceFlow", func() {
		Describe("rawPKCEFlow", func() {
			It("opens the correct authorize url", func() {
				helper := mockedPkceHelper{}
				codeChan := make(chan string)
				callbackURL := "http://localhost:28840/callback"
				helper.On("OpenURL", mock.Anything)
				helper.On("InitCallbackListener", mock.Anything).Return(codeChan, callbackURL)

				go rawPKCEFlow("https://issuer", "testing_client", "testing_api", &helper)

				codeChan <- ""

				helper.AssertExpectations(GinkgoT())
				openedURL := helper.Calls[1].Arguments[0].(string)
				parsedURL, err := url.Parse(openedURL)

				Expect(err).To(BeNil())
				Expect(openedURL[:8]).To(Equal("https://"))
				Expect(parsedURL.Host).To(Equal("issuer"))

				params := parsedURL.Query()
				Expect(len(params)).To(Equal(7))
				Expect(params.Get("audience")).To(Equal("testing_api"))
				Expect(params.Get("scope")).To(Equal("openid offline_access email"))
				Expect(params.Get("response_type")).To(Equal("code"))
				Expect(params.Get("client_id")).To(Equal("testing_client"))
				Expect(params.Get("code_challenge_method")).To(Equal("S256"))
				Expect(params.Get("redirect_uri")).To(Equal("http://localhost:28840/callback"))
			})

			It("inits the callback listener", func() {
				helper := mockedPkceHelper{}
				codeChan := make(chan string)
				callbackURL := "http://localhost:28840/callback"
				helper.On("OpenURL", mock.Anything)
				helper.On("InitCallbackListener", mock.Anything).Return(codeChan, callbackURL)

				go rawPKCEFlow("issuer", "client_id", "aud", &helper)

				codeChan <- "code_yo"
				helper.AssertExpectations(GinkgoT())

				Expect(helper.Calls[0].Arguments[0].(int)).To(Equal(28840))
			})
		})
	})

	Describe("refreshTokenExchanging", func() {
		Describe("httpTokenExchanger", func() {
			It("calls the correct URL with correctly constructed data", func() {
				expectedBody := bytes.NewBufferString(`{"grant_type":"refresh_token","client_id":"abc","refresh_token":"token_yay"}
`)
				resp := &http.Response{
					Body: ioutil.NopCloser(bytes.NewReader([]byte(`{"id_token":"new_id_token_yay"}`))),
				}
				exchanger := mockedHTTPTokenExchanger{}
				exchanger.On("Post", "http://issuer.domain/oauth/token", "application/json", expectedBody).Return(resp, nil)

				idToken := rawRefreshTokenExchangeFlow("http://issuer.domain/", "abc", "token_yay", &exchanger)

				Expect(idToken).To(Equal("new_id_token_yay"))
			})
		})
	})
})
