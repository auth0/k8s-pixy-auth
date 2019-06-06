package auth

import (
	"errors"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func genValidTokenWithExp(exp time.Time) string {
	key := []byte("secret")
	claims := &jwt.StandardClaims{
		ExpiresAt: exp.Unix(),
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}

	return ss
}

type mockCachingProvider struct {
	ReturnToken     *TokenResult
	GetReturnsError error

	CachedToken       *TokenResult
	CacheReturnsError error
}

func (i *mockCachingProvider) GetTokens() (*TokenResult, error) {
	return i.ReturnToken, i.GetReturnsError
}

func (i *mockCachingProvider) CacheTokens(toCache *TokenResult) error {
	i.CachedToken = toCache
	return i.CacheReturnsError
}

type mockTokenProvider struct {
	ReturnRefreshToken      *TokenResult
	ReturnAuthenticateToken *TokenResult
	CalledWithRefreshToken  string
	CalledAuthenticate      bool
	ReturnRefreshError      error
	ReturnAuthenticateError error
}

func (m *mockTokenProvider) Authenticate() (*TokenResult, error) {
	m.CalledAuthenticate = true
	return m.ReturnAuthenticateToken, m.ReturnAuthenticateError
}

func (m *mockTokenProvider) FromRefreshToken(refreshToken string) (*TokenResult, error) {
	m.CalledWithRefreshToken = refreshToken
	return m.ReturnRefreshToken, m.ReturnRefreshError
}

var _ = Describe("CachingTokenProvider", func() {
	var mockCache *mockCachingProvider
	var mockIssuerTokenProvider *mockTokenProvider
	var ctp CachingTokenProvider

	BeforeEach(func() {
		mockCache = &mockCachingProvider{}
		mockIssuerTokenProvider = &mockTokenProvider{}
		ctp = CachingTokenProvider{
			cache:               mockCache,
			issuerTokenProvider: mockIssuerTokenProvider,
		}
	})

	It("returns token result from the cache", func() {
		mockCache.ReturnToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			IDToken:      genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			RefreshToken: genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			ExpiresIn:    20,
		}

		tokenResult, _ := ctp.getTokenResult(func(tr TokenResult) bool { return true })

		Expect(tokenResult).To(Equal(mockCache.ReturnToken))
	})

	It("refreshes token when passed in func says it's invalid", func() {
		mockIssuerTokenProvider.ReturnRefreshToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			IDToken:      genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			RefreshToken: genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			ExpiresIn:    20,
		}
		mockCache.ReturnToken = &TokenResult{
			RefreshToken: "refreshToken",
		}

		tokenResult, _ := ctp.getTokenResult(func(tr TokenResult) bool { return false })

		Expect(mockIssuerTokenProvider.CalledWithRefreshToken).To(Equal(mockCache.ReturnToken.RefreshToken))
		Expect(tokenResult).To(Equal(mockIssuerTokenProvider.ReturnRefreshToken))
	})

	It("runs a full authentication if refresh returns an error", func() {
		mockCache.ReturnToken = &TokenResult{
			RefreshToken: "refreshToken",
		}
		mockIssuerTokenProvider.ReturnRefreshError = errors.New("someerror")
		mockIssuerTokenProvider.ReturnAuthenticateToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			IDToken:      genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			RefreshToken: genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			ExpiresIn:    20,
		}

		tokenResult, _ := ctp.getTokenResult(func(tr TokenResult) bool { return false })

		Expect(mockIssuerTokenProvider.CalledAuthenticate).To(BeTrue())
		Expect(tokenResult).To(Equal(mockIssuerTokenProvider.ReturnAuthenticateToken))
	})

	It("runs authentication when nothing is in the cache", func() {
		mockCache.ReturnToken = nil
		mockIssuerTokenProvider.ReturnAuthenticateToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			IDToken:      genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			RefreshToken: genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			ExpiresIn:    20,
		}

		tokenResult, _ := ctp.getTokenResult(func(tr TokenResult) bool { return false })

		Expect(mockIssuerTokenProvider.CalledAuthenticate).To(BeTrue())
		Expect(tokenResult).To(Equal(mockIssuerTokenProvider.ReturnAuthenticateToken))
	})

	It("caches tokens after authenticating", func() {
		mockIssuerTokenProvider.ReturnAuthenticateToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			IDToken:      genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			RefreshToken: genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			ExpiresIn:    20,
		}

		ctp.getTokenResult(func(tr TokenResult) bool { return false })

		Expect(mockCache.CachedToken).To(Equal(mockIssuerTokenProvider.ReturnAuthenticateToken))
	})

	It("caches the new access and id tokens and orig refresh token after refreshing", func() {
		mockCache.ReturnToken = &TokenResult{
			RefreshToken: "refreshToken",
		}
		mockIssuerTokenProvider.ReturnRefreshToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			IDToken:      genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
			RefreshToken: genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
		}

		ctp.getTokenResult(func(tr TokenResult) bool { return false })

		Expect(mockCache.CachedToken).To(Equal(&TokenResult{
			AccessToken:  mockIssuerTokenProvider.ReturnRefreshToken.AccessToken,
			IDToken:      mockIssuerTokenProvider.ReturnRefreshToken.IDToken,
			RefreshToken: mockCache.ReturnToken.RefreshToken,
		}))
	})

	It("passes along an error from authenticate", func() {
		mockIssuerTokenProvider.ReturnAuthenticateError = errors.New("someerror")

		tokenResult, err := ctp.getTokenResult(func(tr TokenResult) bool { return false })

		Expect(tokenResult).To(BeNil())
		Expect(err.Error()).To(Equal("someerror"))
	})

	It("passes along an error from caching tokens", func() {
		mockCache.CacheReturnsError = errors.New("uh oh")

		tokenResult, err := ctp.getTokenResult(func(tr TokenResult) bool { return false })

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("could not cache tokens: uh oh"))
		Expect(tokenResult).To(BeNil())
	})

	It("passes along an error from the cache when getting tokens returns an error", func() {
		mockCache.GetReturnsError = errors.New("uh oh")

		tokenResult, err := ctp.getTokenResult(func(tr TokenResult) bool { return false })

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("could get tokens from the cache: uh oh"))
		Expect(tokenResult).To(BeNil())
	})

	Describe("GetAccessToken", func() {
		It("refreshes tokens when access token is expired", func() {
			mockCache.ReturnToken = &TokenResult{
				AccessToken:  genValidTokenWithExp(time.Now().Add(time.Second * -50)),
				IDToken:      genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
				RefreshToken: "refreshToken",
			}
			mockIssuerTokenProvider.ReturnRefreshToken = &TokenResult{
				AccessToken: "testToken",
			}

			accessToken, _ := ctp.GetAccessToken()

			Expect(mockIssuerTokenProvider.CalledWithRefreshToken).To(Equal(mockCache.ReturnToken.RefreshToken))
			Expect(accessToken).To(Equal(mockIssuerTokenProvider.ReturnRefreshToken.AccessToken))
		})

		It("returns an error when getTokenResult errors", func() {
			mockIssuerTokenProvider.ReturnAuthenticateError = errors.New("someerror")

			accessToken, err := ctp.GetAccessToken()

			Expect(accessToken).To(BeEmpty())
			Expect(err.Error()).To(Equal("someerror"))
		})
	})

	Describe("GetIDToken", func() {
		It("refreshes tokens when id token is expired", func() {
			mockCache.ReturnToken = &TokenResult{
				AccessToken:  genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
				IDToken:      genValidTokenWithExp(time.Now().Add(time.Second * -50)),
				RefreshToken: "refreshToken",
			}
			mockIssuerTokenProvider.ReturnRefreshToken = &TokenResult{
				IDToken: "testToken",
			}

			idToken, _ := ctp.GetIDToken()

			Expect(mockIssuerTokenProvider.CalledWithRefreshToken).To(Equal(mockCache.ReturnToken.RefreshToken))
			Expect(idToken).To(Equal(mockIssuerTokenProvider.ReturnRefreshToken.IDToken))
		})

		It("returns an error when getTokenResult errors", func() {
			mockIssuerTokenProvider.ReturnAuthenticateError = errors.New("someerror")

			idToken, err := ctp.GetIDToken()

			Expect(idToken).To(BeEmpty())
			Expect(err.Error()).To(Equal("someerror"))
		})
	})

})
