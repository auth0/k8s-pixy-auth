package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// refreshTokenExchangeRequest is the request body needed when exchanging a
// refresh token
type refreshTokenExchangeRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

// refreshTokenExchangeResponse is the response gotten when exchanging a
// refresh token
type refreshTokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

// httpTokenExchanger is used to allow passing in something like http in order
// to exchange a refresh token
type httpTokenExchanger interface {
	Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
}

// buildRefreshTokenExchangeRequest builds the needed refresh token exchange
// request
func buildRefreshTokenExchangeRequest(clientID, refreshToken string) io.Reader {
	rteReq := refreshTokenExchangeRequest{
		GrantType:    "refresh_token",
		ClientID:     clientID,
		RefreshToken: refreshToken,
	}

	rteReqBuffer := new(bytes.Buffer)
	json.NewEncoder(rteReqBuffer).Encode(rteReq)

	return rteReqBuffer
}

// extractIDTokenFrom extracts the id token from the passed in bytes
func extractIDTokenFrom(resp io.Reader) string {
	rteResp := refreshTokenExchangeResponse{}
	err := json.NewDecoder(resp).Decode(&rteResp)
	if err != nil {
		panic(err)
	}

	return rteResp.IDToken
}

// rawRefreshTokenExchangeFlow allows for different mechanics for exchanging a
// refresh token by accepting a tokenExchanger interface which will handle the
// implementation of exchanging the token. It will return the new id token
func rawRefreshTokenExchangeFlow(issuer, clientID, refreshToken string, exchanger httpTokenExchanger) string {
	req := buildRefreshTokenExchangeRequest(clientID, refreshToken)

	resp, err := exchanger.Post(fmt.Sprintf("%voauth/token", issuer), "application/json", req)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	return extractIDTokenFrom(resp.Body)
}

// refreshTokenExchangeFlow takes a issuer, client id, and refresh token and
// exchanges it for an id token
func refreshTokenExchangeFlow(issuer, clientID, refreshToken string) string {
	return rawRefreshTokenExchangeFlow(issuer, clientID, refreshToken, &http.Client{})
}
