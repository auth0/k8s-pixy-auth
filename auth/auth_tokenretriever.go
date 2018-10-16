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

type AuthTokenResponse struct {
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

type RefreshTokenExchangeRequest struct {
	ClientID     string
	RefreshToken string
}

type AuthTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	CodeVerifier string `json:"code_verifier"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
}

type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

type AuthTransport interface {
	Post(url string, body interface{}) (*http.Response, error)
	// TODO: Move into a generic httpClient interface?
	Do(request *http.Request) (*http.Response, error)
}

type HttpClientTransport struct{}

func (t *HttpClientTransport) Do(request *http.Request) (*http.Response, error) {
	return nil, nil
}

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

func (ce *TokenRetriever) newExchangeCodeRequest(req AuthCodeExchangeRequest) (*http.Request, error) {
	body := AuthTokenRequest{
		GrantType:    "authorization_code",
		ClientID:     req.ClientID,
		CodeVerifier: req.CodeVerifier,
		Code:         req.Code,
		RedirectURI:  req.RedirectURI,
	}

	bodyReader := new(bytes.Buffer)
	json.NewEncoder(bodyReader).Encode(body)

	request, err := http.NewRequest("POST",
		fmt.Sprintf("%s/oauth/token", ce.authEndpoint),
		bodyReader,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")

	return request, nil
}

func (ce *TokenRetriever) ExchangeCode(req AuthCodeExchangeRequest) (*TokenResult, error) {
	request, err := ce.newExchangeCodeRequest(req)
	if err != nil {
		return nil, err
	}

	response, err := ce.transport.Do(request)
	if err != nil {
		return nil, err
	}

	return ce.handleExchangeCodeResponse(response)
}

func (ce *TokenRetriever) handleExchangeCodeResponse(resp *http.Response) (*TokenResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("A non-success status code was receveived: %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	atr := AuthTokenResponse{}
	err := json.NewDecoder(resp.Body).Decode(&atr)
	if err != nil {
		return nil, err
	}

	return &TokenResult{
		IDToken:      atr.IDToken,
		RefreshToken: atr.RefreshToken,
		ExpiresIn:    atr.ExpiresIn,
	}, nil
}

func (ce *TokenRetriever) ExchangeRefreshToken(req RefreshTokenExchangeRequest) (*TokenResult, error) {
	body := RefreshTokenRequest{
		GrantType:    "refresh_token",
		ClientID:     req.ClientID,
		RefreshToken: req.RefreshToken,
	}

	resp, _ := ce.transport.Post(
		fmt.Sprintf("%s/oauth/token", ce.authEndpoint),
		body)
	defer resp.Body.Close()

	atr := AuthTokenResponse{}
	err := json.NewDecoder(resp.Body).Decode(&atr)
	if err != nil {
		return nil, err
	}

	return &TokenResult{
		IDToken:      atr.IDToken,
		RefreshToken: req.RefreshToken,
		ExpiresIn:    atr.ExpiresIn,
	}, nil
}
