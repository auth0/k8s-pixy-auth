package auth

import (
	"errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type MockCodeProvider struct {
	Called              bool
	CalledWithState     string
	CalledWithChallenge Challenge
	AuthCodeResult      *AuthorizationCodeResult
	ReturnsError        error
}

func (cp *MockCodeProvider) GetCode(challenge Challenge, state string) (*AuthorizationCodeResult, error) {
	cp.Called = true
	cp.CalledWithState = state
	cp.CalledWithChallenge = challenge
	return cp.AuthCodeResult, cp.ReturnsError
}

type MockTokenExchanger struct {
	CalledWithRequest        *AuthorizationCodeExchangeRequest
	Called                   bool
	ReturnsTokens            *TokenResult
	ReturnsError             error
	RefreshCalledWithRequest *RefreshTokenExchangeRequest
}

func (te *MockTokenExchanger) ExchangeCode(req AuthorizationCodeExchangeRequest) (*TokenResult, error) {
	te.CalledWithRequest = &req
	return te.ReturnsTokens, te.ReturnsError
}

func (te *MockTokenExchanger) ExchangeRefreshToken(req RefreshTokenExchangeRequest) (*TokenResult, error) {
	te.RefreshCalledWithRequest = &req
	return te.ReturnsTokens, te.ReturnsError
}

var _ = Describe("IDTokenProvider", func() {
	issuer := Issuer{
		IssuerEndpoint: "http://issuer",
		ClientID:       "test_clientID",
		Audience:       "test_audience",
	}

	Describe("Authenticate", func() {

		var mockCodeProvider *MockCodeProvider
		var mockTokenExchanger *MockTokenExchanger

		challengeResult := Challenge{
			Code:     "challenge_code_1234",
			Verifier: "verifier_1234",
			Method:   "SHAInfinity",
		}

		mockChallenger := func() Challenge { return challengeResult }

		stateResult := "randomstring1234"
		mockState := func() string { return stateResult }

		BeforeEach(func() {
			mockCodeProvider = &MockCodeProvider{
				AuthCodeResult: &AuthorizationCodeResult{
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
			provider := NewIDTokenProvider(
				issuer,
				mockCodeProvider,
				mockTokenExchanger,
				mockChallenger,
				mockState,
			)

			_, _ = provider.Authenticate()
			Expect(mockCodeProvider.Called).To(BeTrue())
			Expect(mockCodeProvider.CalledWithState).To(Equal(stateResult))
			Expect(mockCodeProvider.CalledWithChallenge).To(Equal(challengeResult))
			Expect(mockTokenExchanger.CalledWithRequest).To(Equal(&AuthorizationCodeExchangeRequest{
				ClientID:     issuer.ClientID,
				CodeVerifier: challengeResult.Verifier,
				Code:         "1234",
				RedirectURI:  "http://callback",
			}))
		})

		It("returns TokensResult from TokenExchanger", func() {
			provider := NewIDTokenProvider(
				issuer,
				mockCodeProvider,
				mockTokenExchanger,
				mockChallenger,
				mockState,
			)

			tokens, _ := provider.Authenticate()

			Expect(tokens).To(Equal(mockTokenExchanger.ReturnsTokens))
		})

		It("returns an error if code request errors", func() {
			mockCodeProvider.ReturnsError = errors.New("someerror")

			provider := NewIDTokenProvider(
				issuer,
				mockCodeProvider,
				mockTokenExchanger,
				mockChallenger,
				mockState,
			)

			_, err := provider.Authenticate()

			Expect(err.Error()).To(Equal("someerror"))
		})

		It("returns an error if token provider errors", func() {
			mockTokenExchanger.ReturnsError = errors.New("someerror")
			mockTokenExchanger.ReturnsTokens = nil

			provider := NewIDTokenProvider(
				issuer,
				mockCodeProvider,
				mockTokenExchanger,
				mockChallenger,
				mockState,
			)

			_, err := provider.Authenticate()

			Expect(err.Error()).To(Equal("someerror"))
		})
	})

	Describe("ExchangeRefreshToken", func() {
		mockTokenExchanger := &MockTokenExchanger{
			ReturnsTokens: &TokenResult{},
		}
		provider := NewIDTokenProvider(
			issuer,
			nil,
			mockTokenExchanger,
			nil,
			nil,
		)

		It("returns the refreshed id token from the TokenExchanger", func() {
			mockTokenExchanger.ReturnsTokens = &TokenResult{
				IDToken: "new token",
			}

			idToken, err := provider.FromRefreshToken("give me a new id token")

			Expect(err).To(BeNil())
			Expect(mockTokenExchanger.RefreshCalledWithRequest).To(Equal(&RefreshTokenExchangeRequest{
				ClientID:     "test_clientID",
				RefreshToken: "give me a new id token",
			}))
			Expect(idToken).To(Equal(mockTokenExchanger.ReturnsTokens))
		})

		It("returns an error when TokenExchanger does", func() {
			mockTokenExchanger.ReturnsError = errors.New("someerror")

			idToken, err := provider.FromRefreshToken("yay")

			Expect(idToken).To(BeNil())
			Expect(err.Error()).To(Equal("someerror"))
		})
	})
})
