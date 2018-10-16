package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockHttpTransport struct {
	PostedUrl     string
	PostedRequest interface{}
	Response      *http.Response
}

func (t *mockHttpTransport) Post(url string, body interface{}) (*http.Response, error) {
	t.PostedUrl = url
	t.PostedRequest = body

	return t.Response, nil
}

func (t *mockHttpTransport) Do(request *http.Request) (*http.Response, error) {
	return nil, nil
}

var _ = Describe("CodetokenExchanger", func() {
	Describe("newExchangeCodeRequest", func() {
		It("creates the request", func() {
			tokenRetriever := TokenRetriever{
				baseURL: "https://issuer",
			}
			exchangeRequest := AuthCodeExchangeRequest{
				ClientID:     "clientID",
				CodeVerifier: "Verifier",
				Code:         "code",
				RedirectURI:  "https://redirect",
			}

			result, err := tokenRetriever.newExchangeCodeRequest(exchangeRequest)

			var tokenRequest AuthTokenRequest
			json.NewDecoder(result.Body).Decode(&tokenRequest)

			Expect(err).To(BeNil())
			Expect(tokenRequest).To(Equal(AuthTokenRequest{
				GrantType:    "authorization_code",
				ClientID:     "clientID",
				CodeVerifier: "Verifier",
				Code:         "code",
				RedirectURI:  "https://redirect",
			}))
			Expect(result.URL.String()).To(Equal("https://issuer/oauth/token"))
		})

		It("returns an error when NewRequest returns an error", func() {
			tokenRetriever := TokenRetriever{
				baseURL: "://issuer",
			}

			result, err := tokenRetriever.newExchangeCodeRequest(AuthCodeExchangeRequest{})

			Expect(result).To(BeNil())
			Expect(err.Error()).To(Equal("parse ://issuer/oauth/token: missing protocol scheme"))
		})
	})

	Describe("handleExhcangeCodeResponse", func() {
		It("handles the response", func() {
			tokenRetriever := TokenRetriever{}
			response := buildResponse(200, AuthTokenResponse{
				ExpiresIn:    1,
				IDToken:      "myIdToken",
				RefreshToken: "myRefreshToken",
			})

			result, err := tokenRetriever.handleExchangeCodeResponse(response)

			Expect(err).To(BeNil())
			Expect(result).To(Equal(&TokenResult{
				ExpiresIn:    1,
				IDToken:      "myIdToken",
				RefreshToken: "myRefreshToken",
			}))
		})

		It("returns error when status code is not successful", func() {
			tokenRetriever := TokenRetriever{}
			response := buildResponse(500, nil)

			result, err := tokenRetriever.handleExchangeCodeResponse(response)

			Expect(result).To(BeNil())
			Expect(err.Error()).To(Equal("A non-success status code was receveived: 500"))
		})

		It("returns error when deserialization fails", func() {
			tokenRetriever := TokenRetriever{}
			response := buildResponse(200, "")

			result, err := tokenRetriever.handleExchangeCodeResponse(response)
			Expect(result).To(BeNil())
			Expect(err.Error()).To(Equal("json: cannot unmarshal string into Go value of type auth.AuthTokenResponse"))
		})
	})

	Describe("ExchangeRefreshToken", func() {
		req := RefreshTokenExchangeRequest{
			ClientID:     "IAMCLIENT",
			RefreshToken: "IAMREFRESHTOKEN",
		}

		It("posts correct request", func() {
			mockTransport := &mockHttpTransport{
				Response: buildResponse(200, nil),
			}

			retriever := NewTokenRetriever("https://issuer", mockTransport)

			retriever.ExchangeRefreshToken(req)

			Expect(mockTransport.PostedUrl).To(Equal("https://issuer/oauth/token"))
			Expect(mockTransport.PostedRequest).To(Equal(RefreshTokenRequest{
				GrantType:    "refresh_token",
				ClientID:     req.ClientID,
				RefreshToken: req.RefreshToken,
			}))
		})

		It("returns tokens from response", func() {
			mockTransport := &mockHttpTransport{
				Response: buildResponse(200, &AuthTokenResponse{
					ExpiresIn: 1000,
					IDToken:   "id_token",
				}),
			}

			retriever := NewTokenRetriever("https://issuer", mockTransport)

			response, err := retriever.ExchangeRefreshToken(req)

			Expect(err).To(BeNil())
			Expect(response).To(Equal(&TokenResult{
				IDToken:      "id_token",
				RefreshToken: req.RefreshToken,
				ExpiresIn:    1000,
			}))
		})
	})
})

func buildResponse(statusCode int, body interface{}) *http.Response {
	b, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}

	resp := &http.Response{
		StatusCode: statusCode,
		Body:       ioutil.NopCloser(bytes.NewReader([]byte(b))),
	}

	return resp
}
