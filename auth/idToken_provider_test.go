package auth_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/auth0/auth0-kubectl-auth/auth"
)

type MockCodeProvider struct {
	Called              bool
	CalledWithChallenge Challenge
	ReturnsCode         string
}

func (cp *MockCodeProvider) GetCode(challenge Challenge) AuthCodeResult {
	cp.Called = true
	cp.CalledWithChallenge = challenge
	return AuthCodeResult{
		cp.ReturnsCode,
		"http://callback",
		nil,
	}
}

type MockTokenProvider struct {
	CalledWithRequest *AuthCodeExchangeRequest
	Called            bool
	ReturnsTokens     TokenResult
}

func (tp *MockTokenProvider) ExchangeCode(req AuthCodeExchangeRequest) (*TokenResult, error) {
	tp.CalledWithRequest = &req
	return &tp.ReturnsTokens, nil
}

var _ = Describe("userIdTokenProvider", func() {
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

	It("Invokes TokenProvider with returned code", func() {
		mockCodeProvider := &MockCodeProvider{
			ReturnsCode: "1234",
		}
		mockTokenProvider := &MockTokenProvider{}

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

	It("Returns TokensResult from TokenProvider", func() {
		mockCodeProvider := &MockCodeProvider{
			ReturnsCode: "1234",
		}
		expectedTokens := TokenResult{IDToken: "idToken", RefreshToken: "refreshToken", ExpiresIn: 1234}
		mockTokenProvider := &MockTokenProvider{
			ReturnsTokens: expectedTokens,
		}

		provider := NewIdTokenProvider(
			issuer,
			mockCodeProvider,
			mockTokenProvider,
			mockChallenger,
		)

		tokens, _ := provider.Authenticate()

		Expect(tokens).To(Equal(&expectedTokens))
	})
})
