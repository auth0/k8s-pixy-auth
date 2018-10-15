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

type MockTokenProvider struct {
	CalledWithRequest *AuthCodeExchangeRequest
	Called            bool
	ReturnsTokens     *TokenResult
	ReturnsError      error
}

func (tp *MockTokenProvider) ExchangeCode(req AuthCodeExchangeRequest) (*TokenResult, error) {
	tp.CalledWithRequest = &req
	return tp.ReturnsTokens, tp.ReturnsError
}

var _ = Describe("userIdTokenProvider", func() {
	var mockCodeProvider *MockCodeProvider
	var mockTokenProvider *MockTokenProvider

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
		mockTokenProvider = &MockTokenProvider{
			ReturnsTokens: &expectedTokens,
		}
	})

	It("invokes TokenProvider with returned code", func() {
		provider := NewIdTokenProvider(
			issuer,
			mockCodeProvider,
			mockTokenProvider,
			mockChallenger,
		)

		_, _ = provider.Authenticate()
		Expect(mockCodeProvider.Called).To(BeTrue())
		Expect(mockCodeProvider.CalledWithChallenge).To(Equal(challengeResult))
		Expect(mockTokenProvider.CalledWithRequest).To(Equal(&AuthCodeExchangeRequest{
			ClientID:     issuer.ClientID,
			CodeVerifier: challengeResult.Verifier,
			Code:         "1234",
			RedirectURI:  "http://callback",
		}))
	})

	It("returns TokensResult from TokenProvider", func() {
		provider := NewIdTokenProvider(
			issuer,
			mockCodeProvider,
			mockTokenProvider,
			mockChallenger,
		)

		tokens, _ := provider.Authenticate()

		Expect(tokens).To(Equal(mockTokenProvider.ReturnsTokens))
	})

	It("returns an error if code request errors", func() {
		mockCodeProvider.ReturnsError = errors.New("someerror")

		provider := NewIdTokenProvider(
			issuer,
			mockCodeProvider,
			mockTokenProvider,
			mockChallenger,
		)

		_, err := provider.Authenticate()

		Expect(err.Error()).To(Equal("someerror"))
	})

	It("returns an error if token provider errors", func() {
		mockTokenProvider.ReturnsError = errors.New("someerror")
		mockTokenProvider.ReturnsTokens = nil

		provider := NewIdTokenProvider(
			issuer,
			mockCodeProvider,
			mockTokenProvider,
			mockChallenger,
		)

		_, err := provider.Authenticate()

		Expect(err.Error()).To(Equal("someerror"))
	})
})
