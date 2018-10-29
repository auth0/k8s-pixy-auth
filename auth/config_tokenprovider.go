package auth

import "fmt"

type configProvider interface {
	GetTokens(identifier string) (string, string)
	SaveTokens(identifier, idToken, refreshToken string)
}

type configBackedCachingProvider struct {
	identifier string
	config     configProvider
}

func NewConfigBackedCachingProvider(clientID, audience string, config configProvider) *configBackedCachingProvider {
	return &configBackedCachingProvider{
		identifier: fmt.Sprintf("%s-%s", clientID, audience),
		config:     config,
	}
}

func (c *configBackedCachingProvider) GetTokens() *TokenResult {
	idToken, refreshToken := c.config.GetTokens(c.identifier)
	return &TokenResult{
		IDToken:      idToken,
		RefreshToken: refreshToken,
	}
}

func (c *configBackedCachingProvider) CacheTokens(toCache *TokenResult) {
	c.config.SaveTokens(c.identifier, toCache.IDToken, toCache.RefreshToken)
}
