package main

type tokenCache interface {
	GetTokens(clientID string) (string, string)
	CacheTokens(clientID, idToken, refreshToken string)
}

// getAuthToken
func getAuthToken(domain, clientID, audience string) string {
	// check config
	// config := newConfig()

	// get token
	// if expired or not exist, flow
	// else return token

	config := newConfigFromFile()
	idToken, _ := config.GetTokens(clientID)

	// TODO: check expiry and refresh with refresh token
	if idToken != "" {
		return idToken
	}

	acr := pkceFlow(domain, clientID, audience)
	// TODO: cache tokens
	return acr.IDToken
}
