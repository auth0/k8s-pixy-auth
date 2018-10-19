package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// TokenRetriever implements AuthTokenExchanger in order to facilitate getting
// Tokens
type TokenRetriever struct {
	baseURL   string
	transport HTTPAuthTransport
}

// AuthorizationTokenResponse is the HTTP response when asking for a new token.
// Note that not all fields will contain data based on what kind of request was
// sent
type AuthorizationTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// AuthorizationCodeExchangeRequest is used to request the exchange of an
// authorization code for a token
type AuthorizationCodeExchangeRequest struct {
	ClientID     string
	CodeVerifier string
	Code         string
	RedirectURI  string
}

// RefreshTokenExchangeRequest is used to request the exchange of a refresh
// token for a refreshed token
type RefreshTokenExchangeRequest struct {
	ClientID     string
	RefreshToken string
}

// AuthorizationTokenRequest is the HTTP request used to exchange an
// authorization code for a token
type AuthorizationTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	CodeVerifier string `json:"code_verifier"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
}

// RefreshTokenRequest is the HTTP request used to exchange a refresh token for
// a refreshed token
type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

// HTTPAuthTransport abstracts how an HTTP exchange request is sent and received
type HTTPAuthTransport interface {
	Do(request *http.Request) (*http.Response, error)
}

// NewTokenRetriever allows a TokenRetriever the internal of a new
// TokenTreriever to be easily set up
func NewTokenRetriever(baseURL string, authTransport HTTPAuthTransport) *TokenRetriever {
	return &TokenRetriever{
		baseURL:   baseURL,
		transport: authTransport,
	}
}

// newExchangeCodeRequest builds a new AuthTokenRequest wrapped in an
// http.Request
func (ce *TokenRetriever) newExchangeCodeRequest(req AuthorizationCodeExchangeRequest) (*http.Request, error) {
	body := AuthorizationTokenRequest{
		GrantType:    "authorization_code",
		ClientID:     req.ClientID,
		CodeVerifier: req.CodeVerifier,
		Code:         req.Code,
		RedirectURI:  req.RedirectURI,
	}

	bodyReader := new(bytes.Buffer)
	json.NewEncoder(bodyReader).Encode(body)

	request, err := http.NewRequest("POST",
		fmt.Sprintf("%s/oauth/token", ce.baseURL),
		bodyReader,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")

	return request, nil
}

// newRefreshTokenRequest builds a new RefreshTokenRequest wrapped in an
// http.Request
func (ce *TokenRetriever) newRefreshTokenRequest(req RefreshTokenExchangeRequest) (*http.Request, error) {
	body := RefreshTokenRequest{
		GrantType:    "refresh_token",
		ClientID:     req.ClientID,
		RefreshToken: req.RefreshToken,
	}

	bodyReader := new(bytes.Buffer)
	json.NewEncoder(bodyReader).Encode(body)

	request, err := http.NewRequest("POST",
		fmt.Sprintf("%s/oauth/token", ce.baseURL),
		bodyReader,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")

	return request, nil
}

// ExchangeCode uses the AuthCodeExchangeRequest to exchange an authorization
// code for tokens
func (ce *TokenRetriever) ExchangeCode(req AuthorizationCodeExchangeRequest) (*TokenResult, error) {
	request, err := ce.newExchangeCodeRequest(req)
	if err != nil {
		return nil, err
	}

	response, err := ce.transport.Do(request)
	if err != nil {
		return nil, err
	}

	return ce.handleAuthTokensResponse(response)
}

// handleAuthTokensResponse takes care of checking an http.Response that has
// auth tokens for errors and parsing the raw body to a TokenResult struct
func (ce *TokenRetriever) handleAuthTokensResponse(resp *http.Response) (*TokenResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("A non-success status code was receveived: %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	atr := AuthorizationTokenResponse{}
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

// ExchangeRefreshToken uses the RefreshTokenExchangeRequest to exchange a
// refresh token for refreshed tokens
func (ce *TokenRetriever) ExchangeRefreshToken(req RefreshTokenExchangeRequest) (*TokenResult, error) {
	request, err := ce.newRefreshTokenRequest(req)
	if err != nil {
		return nil, err
	}

	response, err := ce.transport.Do(request)
	if err != nil {
		return nil, err
	}

	return ce.handleAuthTokensResponse(response)
}
