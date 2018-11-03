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

// CachingTokenProvider satisfies the cmd.tokenProvider interface and is a
// token provider that uses a cache to store tokens
type CachingTokenProvider struct {
	cache               cachingProvider
	accessTokenProvider tokenProvider
}

// NewCachingTokenProvider builds a new CachingTokenProvider using the passed
// in interface satisfiers
func NewCachingTokenProvider(cache cachingProvider, accessTokenProvider tokenProvider) *CachingTokenProvider {
	return &CachingTokenProvider{
		cache:               cache,
		accessTokenProvider: accessTokenProvider,
	}
}

// GetAccessToken returns an access token using the cache and falls back to an
// access token provider if the cache is empty
func (c *CachingTokenProvider) GetAccessToken() (string, error) {
	tokenResult := c.refreshFromCache()

	if tokenResult == nil {
		var err error
		tokenResult, err = c.accessTokenProvider.Authenticate()
		if err != nil {
			return "", err
		}
	}

	c.cache.CacheTokens(tokenResult)

	return tokenResult.AccessToken, nil
}

func (c *CachingTokenProvider) getRefreshToken(refreshToken string) *TokenResult {
	// TODO: log the refreshErr somewhere
	tokenResult, refreshErr := c.accessTokenProvider.FromRefreshToken(refreshToken)
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

	if isValidToken(tokenResult.AccessToken) {
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
