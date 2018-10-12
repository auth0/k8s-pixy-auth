package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type TokenRetriever struct {
	authEndpoint string
	transport    AuthTransport
}

type AuthorizationCodeResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

type AuthCodeExchangeRequest struct {
	ClientID     string
	CodeVerifier string
	Code         string
	RedirectURI  string
}

type AuthTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	CodeVerifier string `json:"code_verifier"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
}

type AuthTransport interface {
	Post(url string, body interface{}) (*http.Response, error)
}

type HttpClientTransport struct{}

func (t *HttpClientTransport) Post(url string, body interface{}) (*http.Response, error) {
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(body)

	resp, err := http.Post(url, "application/json", b)

	return resp, err

	//TODO: Should convert response back to json for client for symmetry purposes
}

func NewTokenRetriever(authEndpoint string, authTransport AuthTransport) *TokenRetriever {
	return &TokenRetriever{
		authEndpoint: authEndpoint,
		transport:    authTransport,
	}
}

func (ce *TokenRetriever) ExchangeCode(req AuthCodeExchangeRequest) (*TokenResult, error) {
	body := AuthTokenRequest{
		GrantType:    "authorization_code",
		ClientID:     req.ClientID,
		CodeVerifier: req.CodeVerifier,
		Code:         req.Code,
		RedirectURI:  req.RedirectURI,
	}

	resp, err := ce.transport.Post(
		fmt.Sprintf("%s/oauth/token", ce.authEndpoint),
		body)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		//TODO: should return error from this function instead.
		panic("A non-success status code was receveived")
	}

	defer resp.Body.Close()

	acr := AuthorizationCodeResponse{}
	err = json.NewDecoder(resp.Body).Decode(&acr)
	if err != nil {
		return nil, err
	}

	return &TokenResult{
		IDToken:      acr.IDToken,
		RefreshToken: acr.RefreshToken,
		ExpiresIn:    acr.ExpiresIn,
	}, nil
}
