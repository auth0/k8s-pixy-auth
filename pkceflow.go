package main

import (
	"github.com/auth0/auth0-kubectl-auth/auth"
)

func pkceFlow(issuer, clientID, audience string) *auth.TokenResult {
	//todo: should be able to get rid of pkce flow and have a default
	// build for AuthCodeProvider that does the right things.
	issuerData := auth.Issuer{
		IssuerEndpoint: issuer,
		ClientID:       clientID,
		Audience:       audience,
	}

	idTokenProvider := auth.NewDefaultIdTokenProvider(issuerData)

	//todo: handle errors better
	tokenResult, err := idTokenProvider.Authenticate()
	if err != nil {
		panic(err)
	}
	return tokenResult
}
