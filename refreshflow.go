package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// RefreshTokenExchangeRequest is the request body needed when exchanging a
// refresh token
type RefreshTokenExchangeRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenExchangeResponse is the response gotten when exchanging a
// refresh token
type RefreshTokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

// TokenExchanger handles the actual implementation of exchanging a refresh
// token
type TokenExchanger interface {
	ExchangeRefreshToken(issuer string, rteReq RefreshTokenExchangeRequest) RefreshTokenExchangeResponse
}

// HTTPTokenExchanger is the HTTP implementation for exchanging a refresh token
type HTTPTokenExchanger struct{}

// ExchangeRefreshToken handles exchanging the refresh token via HTTP
func (hte HTTPTokenExchanger) ExchangeRefreshToken(issuer string, rteReq RefreshTokenExchangeRequest) RefreshTokenExchangeResponse {
	rteReqBuffer := new(bytes.Buffer)
	json.NewEncoder(rteReqBuffer).Encode(rteReq)

	resp, err := http.Post(fmt.Sprintf("%voauth/token", issuer), "application/json", rteReqBuffer)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	rteResp := RefreshTokenExchangeResponse{}
	err = json.NewDecoder(resp.Body).Decode(&rteResp)
	if err != nil {
		panic(err)
	}

	return rteResp
}

// RawRefreshTokenExchangeFlow allows for different mechanics for exchanging a
// refresh token by accepting a tokenExchanger interface which will handle the
// implementation of exchanging the token. It will return the new id token
func RawRefreshTokenExchangeFlow(domain, clientID, refreshToken string, exchanger TokenExchanger) string {
	rteReq := RefreshTokenExchangeRequest{
		GrantType:    "refresh_token",
		ClientID:     clientID,
		RefreshToken: refreshToken,
	}

	rteResp := exchanger.ExchangeRefreshToken(domain, rteReq)
	return rteResp.IDToken
}

// RefreshTokenExchangeFlow takes a domain, client id, and refresh token and
// exchanges it for an id token
func RefreshTokenExchangeFlow(domain, clientID, refreshToken string) string {
	return RawRefreshTokenExchangeFlow(domain, clientID, refreshToken, HTTPTokenExchanger{})
}
