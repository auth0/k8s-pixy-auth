package main

type tokenCache interface {
	GetTokens(clientID string) (string, string)
	CacheTokens(clientID, idToken, refreshToken string)
}

// getAuthInfo
func getAuthInfo(domain, clientID, audience string) string {
	// check config
	// config := newConfig()

	// get token
	// if expired or not exist, flow
	// else return token

	acr := pkceFlow(domain, clientID, audience)
	return acr.IDToken
}
