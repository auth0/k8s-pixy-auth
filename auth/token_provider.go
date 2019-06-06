package auth

import (
	"net/http"

	"github.com/auth0/k8s-pixy-auth/os"
	"github.com/pkg/errors"
)

// TokenProvider takes care of the mechanics needed for getting an access
// Token
type TokenProvider struct {
	allowRefresh bool
	issuerData   Issuer
	codeProvider AuthorizationCodeProvider
	exchanger    AuthorizationTokenExchanger
	challenger   Challenger
}

// AuthorizationCodeProvider abstracts getting an authorization code
type AuthorizationCodeProvider interface {
	GetCode(challenge Challenge, additionalScopes ...string) (*AuthorizationCodeResult, error)
}

// AuthorizationTokenExchanger abstracts exchanging for tokens
type AuthorizationTokenExchanger interface {
	ExchangeCode(req AuthorizationCodeExchangeRequest) (*TokenResult, error)
	ExchangeRefreshToken(req RefreshTokenExchangeRequest) (*TokenResult, error)
}

// TokenResult holds token information
type TokenResult struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// Issuer holds information about the issuer of tokens
type Issuer struct {
	IssuerEndpoint string
	ClientID       string
	Audience       string
}

// NewAccessTokenProvider allows for the easy setup AccessTokenProvider
func NewAccessTokenProvider(
	allowRefresh bool,
	issuerData Issuer,
	codeProvider AuthorizationCodeProvider,
	exchanger AuthorizationTokenExchanger,
	challenger Challenger) *TokenProvider {
	return &TokenProvider{
		allowRefresh: allowRefresh,
		issuerData:   issuerData,
		codeProvider: codeProvider,
		exchanger:    exchanger,
		challenger:   challenger,
	}
}

// NewDefaultAccessTokenProvider provides an easy way to build up a default
// token provider with all the correct configuration. If refresh tokens should
// be allowed pass in true for <allowRefresh>
func NewDefaultAccessTokenProvider(issuerData Issuer, allowRefresh bool) (*TokenProvider, error) {
	wellKnownEndpoints, err := GetOIDCWellKnownEndpointsFromIssuerURL(issuerData.IssuerEndpoint)
	if err != nil {
		return nil, err
	}

	codeProvider := NewLocalhostCodeProvider(
		issuerData,
		*wellKnownEndpoints,
		NewLocalhostCallbackListener(8080),
		&os.DefaultInteractor{},
		DefaultStateGenerator,
	)

	tokenRetriever := NewTokenRetriever(
		*wellKnownEndpoints,
		&http.Client{})

	return NewAccessTokenProvider(
		allowRefresh,
		issuerData,
		codeProvider,
		tokenRetriever,
		DefaultChallengeGenerator), nil
}

// Authenticate is used to retrieve a TokenResult when the user has not yet
// authenticated
func (p *TokenProvider) Authenticate() (*TokenResult, error) {
	challenge := p.challenger()

	var additionalScopes []string
	if p.allowRefresh {
		additionalScopes = append(additionalScopes, "offline_access")
	}

	codeResult, err := p.codeProvider.GetCode(challenge, additionalScopes...)
	if err != nil {
		return nil, err
	}

	exchangeRequest := AuthorizationCodeExchangeRequest{
		Code:         codeResult.Code,
		CodeVerifier: challenge.Verifier,
		ClientID:     p.issuerData.ClientID,
		RedirectURI:  codeResult.RedirectURI,
	}

	tokenResult, err := p.exchanger.ExchangeCode(exchangeRequest)
	if err != nil {
		return nil, errors.Wrap(err, "could not exchange code")
	}

	return tokenResult, nil
}

// FromRefreshToken is used to retrieve a TokenResult when the user has already
// authenticated but their Access Token has expired
func (p *TokenProvider) FromRefreshToken(refreshToken string) (*TokenResult, error) {
	if !p.allowRefresh {
		return nil, errors.New("cannot use refresh token as it was not allowed to be used by the client")
	}

	exchangeRequest := RefreshTokenExchangeRequest{
		ClientID:     p.issuerData.ClientID,
		RefreshToken: refreshToken,
	}

	tokenResult, err := p.exchanger.ExchangeRefreshToken(exchangeRequest)
	if err != nil {
		return nil, err
	}

	return tokenResult, nil
}
