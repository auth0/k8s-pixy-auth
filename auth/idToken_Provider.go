package auth

import (
	"net/http"

	"github.com/auth0/auth0-kubectl-auth/os"
)

// IDTokenProvider takes care of the mechanics needed for getting an ID Token
type IDTokenProvider struct {
	issuerData   Issuer
	codeProvider AuthCodeProvider
	exchanger    AuthTokenExchanger
	challenger   Challenger
}

// AuthCodeProvider abstracts getting an authorization code
type AuthCodeProvider interface {
	GetCode(challenge Challenge) (*AuthCodeResult, error)
}

// AuthTokenExchanger abstracts exchanging for tokens
type AuthTokenExchanger interface {
	ExchangeCode(req AuthCodeExchangeRequest) (*TokenResult, error)
	ExchangeRefreshToken(req RefreshTokenExchangeRequest) (*TokenResult, error)
}

// TokenResult holds token information
type TokenResult struct {
	IDToken      string
	RefreshToken string
	ExpiresIn    int
}

// Issuer holds information about the issuer of tokens
type Issuer struct {
	IssuerEndpoint string
	ClientID       string
	Audience       string
}

// NewIDTokenProvider allows for the easy setup IDTokenProvider
func NewIDTokenProvider(
	issuerData Issuer,
	codeProvider AuthCodeProvider,
	exchanger AuthTokenExchanger,
	challenger Challenger) *IDTokenProvider {
	return &IDTokenProvider{
		issuerData:   issuerData,
		codeProvider: codeProvider,
		exchanger:    exchanger,
		challenger:   challenger,
	}
}

// NewDefaultIDTokenProvider provides an easy way to build up a default token provider with
// all the correct configuration.
func NewDefaultIDTokenProvider(issuerData Issuer) *IDTokenProvider {
	codeProvider := NewLocalhostCodeProvider(
		issuerData,
		NewLocalhostCallbackListener(8080),
		&os.DefaultInteractor{})

	tokenRetriever := NewTokenRetriever(
		issuerData.IssuerEndpoint,
		&http.Client{})

	return NewIDTokenProvider(
		issuerData,
		codeProvider,
		tokenRetriever,
		DefaultChallengeGenerator)
}

// Authenticate is used to retrieve a TokenResult when the user has not yet
// authenticated
func (p *IDTokenProvider) Authenticate() (*TokenResult, error) {
	challenge := p.challenger()
	codeResult, err := p.codeProvider.GetCode(challenge)

	if err != nil {
		return nil, err
	}

	exchangeRequest := AuthCodeExchangeRequest{
		Code:         codeResult.Code,
		CodeVerifier: challenge.Verifier,
		ClientID:     p.issuerData.ClientID,
		RedirectURI:  codeResult.RedirectURI,
	}

	tokenResult, err := p.exchanger.ExchangeCode(exchangeRequest)
	if err != nil {
		return nil, err
	}

	return tokenResult, nil
}

// FromRefreshToken is used to retrieve a TokenResult when the user has already
// authenticated but their ID Token has expired
func (p *IDTokenProvider) FromRefreshToken(refreshToken string) (*TokenResult, error) {
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
