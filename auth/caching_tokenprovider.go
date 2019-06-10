package auth

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

type cachingProvider interface {
	GetTokens() (*TokenResult, error)
	CacheTokens(*TokenResult) error
}

type issuerTokenProvider interface {
	FromRefreshToken(refreshToken string) (*TokenResult, error)
	Authenticate() (*TokenResult, error)
}

// CachingTokenProvider satisfies the cmd.tokenProvider interface and is a
// token provider that uses a cache to store tokens
type CachingTokenProvider struct {
	cache               cachingProvider
	issuerTokenProvider issuerTokenProvider
}

// NewCachingTokenProvider builds a new CachingTokenProvider using the passed
// in interface satisfiers
func NewCachingTokenProvider(cache cachingProvider, issuerTokenProvider issuerTokenProvider) *CachingTokenProvider {
	return &CachingTokenProvider{
		cache:               cache,
		issuerTokenProvider: issuerTokenProvider,
	}
}

func (c *CachingTokenProvider) getTokenResult(shouldRefresh func(TokenResult) bool) (*TokenResult, error) {
	tokenResult, err := c.refreshFromCache(shouldRefresh)
	if err != nil {
		return nil, err
	}

	if tokenResult == nil {
		tokenResult, err = c.issuerTokenProvider.Authenticate()
		if err != nil {
			return nil, err
		}
	}

	err = c.cache.CacheTokens(tokenResult)
	if err != nil {
		return nil, errors.Wrap(err, "could not cache tokens")
	}

	return tokenResult, nil
}

// GetIDToken returns an id token using the cache and falls back to an
// issuer token provider if the cache is empty
func (c *CachingTokenProvider) GetIDToken() (string, error) {
	isIDTokenValid := func(tokenResult TokenResult) bool { return isValidToken(tokenResult.IDToken) }
	tokenResult, err := c.getTokenResult(isIDTokenValid)
	if err != nil {
		return "", err
	}

	return tokenResult.IDToken, nil
}

// GetAccessToken returns an access token using the cache and falls back to an
// issuer token provider if the cache is empty
func (c *CachingTokenProvider) GetAccessToken() (string, error) {
	isAccessTokenValid := func(tokenResult TokenResult) bool { return isValidToken(tokenResult.AccessToken) }
	tokenResult, err := c.getTokenResult(isAccessTokenValid)
	if err != nil {
		return "", err
	}

	return tokenResult.AccessToken, nil
}

func (c *CachingTokenProvider) getRefreshToken(refreshToken string) *TokenResult {
	// TODO: log the refreshErr somewhere
	tokenResult, refreshErr := c.issuerTokenProvider.FromRefreshToken(refreshToken)
	if refreshErr != nil {
		return nil
	}

	tokenResult.RefreshToken = refreshToken

	return tokenResult
}

func (c *CachingTokenProvider) refreshFromCache(isTokenValid func(TokenResult) bool) (*TokenResult, error) {
	tokenResult, err := c.cache.GetTokens()
	if err != nil {
		return nil, errors.Wrap(err, "could get tokens from the cache")
	}

	if tokenResult == nil {
		return nil, nil
	}

	if isTokenValid(*tokenResult) {
		return tokenResult, nil
	}

	if tokenResult.RefreshToken == "" {
		return nil, nil
	}

	return c.getRefreshToken(tokenResult.RefreshToken), nil
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
