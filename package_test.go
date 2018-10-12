package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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
	Response *http.Response
}

func (m *mockedHTTPTokenExchanger) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	args := m.Called(url, contentType, body)
	return m.Response, args.Error(0)
}

type mockedAuthorizationFlowHelper struct {
	mock.Mock
	CallbackURL string
	CodeChan    chan string
}

func (m *mockedAuthorizationFlowHelper) InitCallbackListener(port int) chan string {
	m.Called(port)
	return m.CodeChan
}

func (m *mockedAuthorizationFlowHelper) OpenURL(url string) error {
	args := m.Called(url)
	return args.Error(0)
}

func (m *mockedAuthorizationFlowHelper) GetCallbackURL() string {
	return m.CallbackURL
}

func (m *mockedAuthorizationFlowHelper) CompleteAuthorization(code string) {
	m.CodeChan <- code
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
		Describe("getAuthorizationCode", func() {
			var helper mockedAuthorizationFlowHelper

			BeforeEach(func() {
				helper = mockedAuthorizationFlowHelper{
					CallbackURL: "http://localhost:28840/callback",
					CodeChan:    make(chan string),
				}
				helper.On("InitCallbackListener", mock.Anything)
				helper.On("OpenURL", mock.Anything).Return(nil)
			})

			It("opens the correct authorize url", func() {
				go getAuthorizationCode("https://issuer", "testing_client", "testing_api", "challenge_yo", "S256", &helper)
				helper.CompleteAuthorization("")
				helper.AssertExpectations(GinkgoT())

				openedURL := helper.Calls[1].Arguments[0].(string)
				parsedURL, err := url.Parse(openedURL)

				Expect(err).To(BeNil())
				Expect(parsedURL.Scheme).To(Equal("https"))
				Expect(parsedURL.Host).To(Equal("issuer"))

				params := parsedURL.Query()
				Expect(len(params)).To(Equal(7))
				Expect(params.Get("audience")).To(Equal("testing_api"))
				Expect(params.Get("scope")).To(Equal("openid offline_access email"))
				Expect(params.Get("response_type")).To(Equal("code"))
				Expect(params.Get("client_id")).To(Equal("testing_client"))
				Expect(params.Get("code_challenge")).To(Equal("challenge_yo"))
				Expect(params.Get("code_challenge_method")).To(Equal("S256"))
				Expect(params.Get("redirect_uri")).To(Equal(helper.CallbackURL))
			})

			It("handles listening for and returning the auth code", func() {
				gacCodeChan := make(chan string)

				go func() {
					gacCodeChan <- getAuthorizationCode("", "", "", "", "", &helper)
				}()
				helper.CompleteAuthorization("code_yo")
				returnedCode := <-gacCodeChan
				helper.AssertExpectations(GinkgoT())

				Expect(returnedCode).To(Equal("code_yo"))
				Expect(helper.Calls[0].Arguments[0].(int)).To(Equal(28840))
			})
		})

		Describe("exchangeAuthorizationCodeForIDAndRefreshToken", func() {
			var exchanger mockedHTTPTokenExchanger

			BeforeEach(func() {
				exchanger = mockedHTTPTokenExchanger{
					Response: &http.Response{
						Body: ioutil.NopCloser(bytes.NewReader([]byte("{}"))),
					},
				}
				exchanger.On("Post", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			})

			It("calls the correct URL with the correctly constructed data", func() {
				expectedBody := `{"grant_type":"authorization_code","client_id":"abc","code_verifier":"verification_yo","code":"this_is_the_code","redirect_uri":"http://localhost:28840/callback"}
`
				exchangeAuthorizationCodeForIDAndRefreshToken("http://issuer.domain", "abc", "verification_yo", "this_is_the_code", "http://localhost:28840/callback", &exchanger)

				exchanger.AssertExpectations(GinkgoT())

				postArgs := exchanger.Calls[0].Arguments
				Expect(postArgs[0].(string)).To(Equal("http://issuer.domain/oauth/token"))
				Expect(postArgs[1].(string)).To(Equal("application/json"))
				body := postArgs[2].(*bytes.Buffer)
				Expect(body.String()).To(Equal(expectedBody))
			})

			It("returns the id and refresh token from the post response", func() {
				exchanger.Response.Body = ioutil.NopCloser(bytes.NewReader([]byte(`{"access_token":"access_token_yay","refresh_token":"refresh_token_yay","id_token":"id_token_yay","token_type":"Bearer"}`)))

				idToken, refreshToken := exchangeAuthorizationCodeForIDAndRefreshToken("", "", "", "", "", &exchanger)

				exchanger.AssertExpectations(GinkgoT())

				Expect(idToken).To(Equal("id_token_yay"))
				Expect(refreshToken).To(Equal("refresh_token_yay"))
			})
		})
	})

	Describe("refreshTokenExchanging", func() {
		Describe("httpTokenExchanger", func() {
			It("calls the correct URL with correctly constructed data", func() {
				expectedBody := bytes.NewBufferString(`{"grant_type":"refresh_token","client_id":"abc","refresh_token":"token_yay"}
`)
				exchanger := mockedHTTPTokenExchanger{
					Response: &http.Response{
						Body: ioutil.NopCloser(bytes.NewReader([]byte(`{"id_token":"new_id_token_yay"}`))),
					},
				}
				exchanger.On("Post", "http://issuer.domain/oauth/token", "application/json", expectedBody).Return(nil)

				idToken := rawRefreshTokenExchangeFlow("http://issuer.domain/", "abc", "token_yay", &exchanger)

				Expect(idToken).To(Equal("new_id_token_yay"))
			})
		})
	})

	Describe("generateChallenge", func() {
		It("generates challenge and verifier", func() {
			challenge := generateChallenge(32)

			csum := sha256.Sum256([]byte(challenge.Verifier))
			expectedChallenge := base64.RawURLEncoding.EncodeToString(csum[:])

			Expect(challenge.Challenge).To(Equal(expectedChallenge))
			Expect(challenge.Algorithm).To(Equal("S256"))
			v, _ := base64.RawURLEncoding.DecodeString(challenge.Verifier)
			Expect(len(v)).To(Equal(32))
		})
	})
})
