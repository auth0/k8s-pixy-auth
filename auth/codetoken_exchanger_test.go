package auth_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	. "github.com/auth0/auth0-kubectl-auth/auth"
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

var _ = Describe("CodetokenExchanger", func() {
	req := AuthCodeExchangeRequest{
		ClientID:     "clientID",
		CodeVerifier: "Verifier",
		Code:         "code",
		RedirectURI:  "https://redirect",
	}

	It("posts correct request", func() {
		mockTransport := &mockHttpTransport{
			Response: buildResponse(200, nil),
		}

		retriever := NewTokenRetriever("https://issuer", mockTransport)

		retriever.ExchangeCode(req)

		Expect(mockTransport.PostedUrl).To(Equal("https://issuer/oauth/token"))
		Expect(mockTransport.PostedRequest).To(Equal(AuthTokenRequest{
			GrantType:    "authorization_code",
			Code:         req.Code,
			ClientID:     req.ClientID,
			CodeVerifier: req.CodeVerifier,
			RedirectURI:  req.RedirectURI,
		}))
	})

	It("returns tokens from response", func() {
		mockTransport := &mockHttpTransport{
			Response: buildResponse(200, &AuthorizationCodeResponse{
				ExpiresIn:    1000,
				IDToken:      "id_token",
				RefreshToken: "refresh_token",
			}),
		}

		retriever := NewTokenRetriever("https://issuer", mockTransport)

		response, err := retriever.ExchangeCode(req)

		Expect(err).To(BeNil())
		Expect(response).To(Equal(&TokenResult{
			IDToken:      "id_token",
			RefreshToken: "refresh_token",
			ExpiresIn:    1000,
		}))
	})

	// It("handles request errors")
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
