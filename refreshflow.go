package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type refreshTokenExchange struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

type refreshTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func refreshFlow(domain, clientID, refreshToken string) string {
	rtExchange := refreshTokenExchange{
		GrantType:    "refresh_token",
		ClientID:     clientID,
		RefreshToken: refreshToken,
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(rtExchange)

	resp, err := http.Post(fmt.Sprintf("https://%v/oauth/token", domain), "application/json", b)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	rtr := refreshTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(&rtr)
	if err != nil {
		panic(err)
	}

	return rtr.IDToken
}
