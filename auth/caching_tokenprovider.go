package auth

import (
	jwt "github.com/dgrijalva/jwt-go"
)

type cachingProvider interface {
	GetTokens() (*TokenResult, error)
}

type tokenProvider interface {
	FromRefreshToken(refreshToken string) (*TokenResult, error)
}

type cachingTokenProvider struct {
	cache           cachingProvider
	idTokenProvider tokenProvider
}

func (c *cachingTokenProvider) GetIDToken() string {
	tokenResult, _ := c.cache.GetTokens()

	p := jwt.Parser{}
	if _, _, err := p.ParseUnverified(tokenResult.IDToken, jwt.MapClaims{}); err != nil {
		tokenResult, _ = c.idTokenProvider.FromRefreshToken(tokenResult.RefreshToken)
	}

	return tokenResult.IDToken
}
