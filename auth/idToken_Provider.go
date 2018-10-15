package auth

import "github.com/auth0/auth0-kubectl-auth/os"

type IdTokenProvider struct {
	issuerData   Issuer
	codeProvider AuthCodeProvider
	exchanger    AuthTokenExchanger
	challenger   Challenger
}

type AuthCodeProvider interface {
	GetCode(challenge Challenge) (*AuthCodeResult, error)
}
type AuthTokenExchanger interface {
	ExchangeCode(req AuthCodeExchangeRequest) (*TokenResult, error)
}

type TokenResult struct {
	IDToken      string
	RefreshToken string
	ExpiresIn    int
}

type Issuer struct {
	IssuerEndpoint string
	ClientID       string
	Audience       string
}

func NewIdTokenProvider(
	issuerData Issuer,
	codeProvider AuthCodeProvider,
	exchanger AuthTokenExchanger,
	challenger Challenger) *IdTokenProvider {
	return &IdTokenProvider{
		issuerData:   issuerData,
		codeProvider: codeProvider,
		exchanger:    exchanger,
		challenger:   challenger,
	}
}

// NewDefaultIdTokenProvider provides an easy way to build up a default token provider with
// all the correct configuration.
func NewDefaultIdTokenProvider(issuerData Issuer) *IdTokenProvider {
	codeProvider := NewAuthCodeProvider(
		issuerData,
		NewLocalhostCallbackListener(8080),
		&os.DefaultInteractor{})

	tokenRetriever := NewTokenRetriever(
		issuerData.IssuerEndpoint,
		&HttpClientTransport{})

	return NewIdTokenProvider(
		issuerData,
		codeProvider,
		tokenRetriever,
		DefaultChallengeGenerator)
}

func (p *IdTokenProvider) Authenticate() (*TokenResult, error) {
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
