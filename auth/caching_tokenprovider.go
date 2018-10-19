package auth

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type cachingProvider interface {
	GetTokens() *TokenResult
	CacheTokens(*TokenResult)
}

type tokenProvider interface {
	FromRefreshToken(refreshToken string) (*TokenResult, error)
	Authenticate() (*TokenResult, error)
}

type CachingTokenProvider struct {
	cache           cachingProvider
	idTokenProvider tokenProvider
}

func NewCachingTokenProvider(cache cachingProvider, idTokenProvider tokenProvider) *CachingTokenProvider {
	return &CachingTokenProvider{
		cache:           cache,
		idTokenProvider: idTokenProvider,
	}
}

func (c *CachingTokenProvider) GetIDToken() (string, error) {
	tokenResult := c.refreshFromCache()

	if tokenResult == nil {
		var err error
		tokenResult, err = c.idTokenProvider.Authenticate()
		if err != nil {
			return "", err
		}
	}

	c.cache.CacheTokens(tokenResult)

	return tokenResult.IDToken, nil
}

func (c *CachingTokenProvider) getRefreshToken(refreshToken string) *TokenResult {
	// TODO: log the refreshErr somewhere
	tokenResult, refreshErr := c.idTokenProvider.FromRefreshToken(refreshToken)
	if refreshErr != nil {
		return nil
	}

	tokenResult.RefreshToken = refreshToken

	return tokenResult
}

func (c *CachingTokenProvider) refreshFromCache() *TokenResult {
	tokenResult := c.cache.GetTokens()

	if tokenResult == nil {
		return nil
	}

	if isValidToken(tokenResult.IDToken) {
		return tokenResult
	}

	if tokenResult.RefreshToken == "" {
		return nil
	}

	return c.getRefreshToken(tokenResult.RefreshToken)
}

// isValidToken checks to see if the token is valid and has not expired
func isValidToken(token string) bool {
	p := jwt.Parser{}
	claims := jwt.MapClaims{}

	if _, _, err := p.ParseUnverified(token, claims); err != nil {
		return false
	}

	return claims.VerifyExpiresAt(time.Now().Unix(), true)
}
