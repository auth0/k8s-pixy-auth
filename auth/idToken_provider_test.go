package auth_test

import (
	"errors"

	. "github.com/auth0/auth0-kubectl-auth/auth"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type MockCodeProvider struct {
	Called              bool
	CalledWithChallenge Challenge
	AuthCodeResult      *AuthCodeResult
	ReturnsError        error
}

func (cp *MockCodeProvider) GetCode(challenge Challenge) (*AuthCodeResult, error) {
	cp.Called = true
	cp.CalledWithChallenge = challenge
	return cp.AuthCodeResult, cp.ReturnsError
}

type MockTokenExchanger struct {
	CalledWithRequest *AuthCodeExchangeRequest
	Called            bool
	ReturnsTokens     *TokenResult
	ReturnsError      error
}

func (te *MockTokenExchanger) ExchangeCode(req AuthCodeExchangeRequest) (*TokenResult, error) {
	te.CalledWithRequest = &req
	return te.ReturnsTokens, te.ReturnsError
}

var _ = Describe("userIdTokenProvider", func() {
	var mockCodeProvider *MockCodeProvider
	var mockTokenExchanger *MockTokenExchanger

	challengeResult := Challenge{
		Code:     "challenge_code_1234",
		Verifier: "verifier_1234",
		Method:   "SHAInfinity",
	}

	issuer := Issuer{
		IssuerEndpoint: "http://issuer",
		ClientID:       "test_clientID",
		Audience:       "test_audience",
	}

	mockChallenger := func() Challenge { return challengeResult }

	BeforeEach(func() {
		mockCodeProvider = &MockCodeProvider{
			AuthCodeResult: &AuthCodeResult{
				Code:        "1234",
				RedirectURI: "http://callback",
			},
		}

		expectedTokens := TokenResult{IDToken: "idToken", RefreshToken: "refreshToken", ExpiresIn: 1234}
		mockTokenExchanger = &MockTokenExchanger{
			ReturnsTokens: &expectedTokens,
		}
	})

	It("invokes TokenExchanger with returned code", func() {
		provider := NewIdTokenProvider(
			issuer,
			mockCodeProvider,
			mockTokenExchanger,
			mockChallenger,
		)

		_, _ = provider.Authenticate()
		Expect(mockCodeProvider.Called).To(BeTrue())
		Expect(mockCodeProvider.CalledWithChallenge).To(Equal(challengeResult))
		Expect(mockTokenExchanger.CalledWithRequest).To(Equal(&AuthCodeExchangeRequest{
			ClientID:     issuer.ClientID,
			CodeVerifier: challengeResult.Verifier,
			Code:         "1234",
			RedirectURI:  "http://callback",
		}))
	})

	It("returns TokensResult from TokenExchanger", func() {
		provider := NewIdTokenProvider(
			issuer,
			mockCodeProvider,
			mockTokenExchanger,
			mockChallenger,
		)

		tokens, _ := provider.Authenticate()

		Expect(tokens).To(Equal(mockTokenExchanger.ReturnsTokens))
	})

	It("returns an error if code request errors", func() {
		mockCodeProvider.ReturnsError = errors.New("someerror")

		provider := NewIdTokenProvider(
			issuer,
			mockCodeProvider,
			mockTokenExchanger,
			mockChallenger,
		)

		_, err := provider.Authenticate()

		Expect(err.Error()).To(Equal("someerror"))
	})

	It("returns an error if token provider errors", func() {
		mockTokenExchanger.ReturnsError = errors.New("someerror")
		mockTokenExchanger.ReturnsTokens = nil

		provider := NewIdTokenProvider(
			issuer,
			mockCodeProvider,
			mockTokenExchanger,
			mockChallenger,
		)

		_, err := provider.Authenticate()

		Expect(err.Error()).To(Equal("someerror"))
	})
})
