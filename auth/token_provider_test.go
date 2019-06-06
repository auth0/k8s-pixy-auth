package auth

import (
	"errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type MockCodeProvider struct {
	Called                     bool
	CalledWithChallenge        Challenge
	CalledWithAdditionalScopes []string
	AuthCodeResult             *AuthorizationCodeResult
	ReturnsError               error
}

func (cp *MockCodeProvider) GetCode(challenge Challenge, additionalScopes ...string) (*AuthorizationCodeResult, error) {
	cp.Called = true
	cp.CalledWithChallenge = challenge
	cp.CalledWithAdditionalScopes = additionalScopes
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

var _ = Describe("AccessTokenProvider", func() {
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

		BeforeEach(func() {
			mockCodeProvider = &MockCodeProvider{
				AuthCodeResult: &AuthorizationCodeResult{
					Code:        "1234",
					RedirectURI: "http://callback",
				},
			}

			expectedTokens := TokenResult{AccessToken: "accessToken", RefreshToken: "refreshToken", ExpiresIn: 1234}
			mockTokenExchanger = &MockTokenExchanger{
				ReturnsTokens: &expectedTokens,
			}
		})

		It("invokes TokenExchanger with returned code", func() {
			provider := NewAccessTokenProvider(
				false,
				issuer,
				mockCodeProvider,
				mockTokenExchanger,
				mockChallenger,
			)

			_, _ = provider.Authenticate()
			Expect(mockCodeProvider.Called).To(BeTrue())
			Expect(mockCodeProvider.CalledWithChallenge).To(Equal(challengeResult))
			Expect(mockTokenExchanger.CalledWithRequest).To(Equal(&AuthorizationCodeExchangeRequest{
				ClientID:     issuer.ClientID,
				CodeVerifier: challengeResult.Verifier,
				Code:         "1234",
				RedirectURI:  "http://callback",
			}))
			Expect(len(mockCodeProvider.CalledWithAdditionalScopes)).To(Equal(0))
		})

		It("sends the offline_access scope when refresh tokens are wanted", func() {
			provider := NewAccessTokenProvider(
				true,
				issuer,
				mockCodeProvider,
				mockTokenExchanger,
				mockChallenger,
			)

			_, _ = provider.Authenticate()
			Expect(mockCodeProvider.Called).To(BeTrue())
			Expect(mockCodeProvider.CalledWithChallenge).To(Equal(challengeResult))
			Expect(mockTokenExchanger.CalledWithRequest).To(Equal(&AuthorizationCodeExchangeRequest{
				ClientID:     issuer.ClientID,
				CodeVerifier: challengeResult.Verifier,
				Code:         "1234",
				RedirectURI:  "http://callback",
			}))
			Expect(mockCodeProvider.CalledWithAdditionalScopes).To(Equal([]string{"offline_access"}))
		})

		It("returns TokensResult from TokenExchanger", func() {
			provider := NewAccessTokenProvider(
				false,
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

			provider := NewAccessTokenProvider(
				false,
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

			provider := NewAccessTokenProvider(
				false,
				issuer,
				mockCodeProvider,
				mockTokenExchanger,
				mockChallenger,
			)

			_, err := provider.Authenticate()

			Expect(err.Error()).To(Equal("could not exchange code: someerror"))
		})
	})

	Describe("ExchangeRefreshToken", func() {
		var mockTokenExchanger *MockTokenExchanger
		var provider *TokenProvider

		BeforeEach(func() {
			mockTokenExchanger = &MockTokenExchanger{
				ReturnsTokens: &TokenResult{},
			}
			provider = NewAccessTokenProvider(
				true,
				issuer,
				nil,
				mockTokenExchanger,
				nil,
			)
		})

		It("returns the refreshed access token from the TokenExchanger", func() {
			mockTokenExchanger.ReturnsTokens = &TokenResult{
				AccessToken: "new token",
			}

			accessToken, err := provider.FromRefreshToken("give me a new access token")

			Expect(err).To(BeNil())
			Expect(mockTokenExchanger.RefreshCalledWithRequest).To(Equal(&RefreshTokenExchangeRequest{
				ClientID:     "test_clientID",
				RefreshToken: "give me a new access token",
			}))
			Expect(accessToken).To(Equal(mockTokenExchanger.ReturnsTokens))
		})

		It("returns an error when TokenExchanger does", func() {
			mockTokenExchanger.ReturnsError = errors.New("someerror")

			accessToken, err := provider.FromRefreshToken("yay")

			Expect(accessToken).To(BeNil())
			Expect(err.Error()).To(Equal("someerror"))
		})

		It("returns an error when refresh tokens are not allowed", func() {
			provider.allowRefresh = false

			accessToken, err := provider.FromRefreshToken("yay")

			Expect(accessToken).To(BeNil())
			Expect(err.Error()).To(Equal("cannot use refresh token as it was not allowed to be used by the client"))
		})
	})
})
