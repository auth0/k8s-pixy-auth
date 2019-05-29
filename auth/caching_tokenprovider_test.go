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
	var accessTokenProvider *mockTokenProvider
	var ctp CachingTokenProvider

	BeforeEach(func() {
		mockCache = &mockCachingProvider{}
		accessTokenProvider = &mockTokenProvider{}
		ctp = CachingTokenProvider{
			cache:               mockCache,
			accessTokenProvider: accessTokenProvider,
		}
	})

	It("returns an access token from the cache", func() {
		mockCache.ReturnToken = &TokenResult{
			AccessToken: genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessToken).To(Equal(mockCache.ReturnToken.AccessToken))
	})

	It("refreshes token when access token is invalid", func() {
		accessTokenProvider.ReturnRefreshToken = &TokenResult{
			AccessToken: "testToken",
		}
		mockCache.ReturnToken = &TokenResult{
			RefreshToken: "refreshToken",
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessTokenProvider.CalledWithRefreshToken).To(Equal(mockCache.ReturnToken.RefreshToken))
		Expect(accessToken).To(Equal(accessTokenProvider.ReturnRefreshToken.AccessToken))
	})

	It("runs a full authentication if refresh returns an error", func() {
		mockCache.ReturnToken = &TokenResult{
			RefreshToken: "refreshToken",
		}
		accessTokenProvider.ReturnRefreshError = errors.New("someerror")
		accessTokenProvider.ReturnAuthenticateToken = &TokenResult{
			AccessToken: "testToken",
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessTokenProvider.CalledAuthenticate).To(BeTrue())
		Expect(accessToken).To(Equal(accessTokenProvider.ReturnAuthenticateToken.AccessToken))
	})

	It("refreshes token when access token is expired", func() {
		mockCache.ReturnToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Second * -50)),
			RefreshToken: "refreshToken",
		}
		accessTokenProvider.ReturnRefreshToken = &TokenResult{
			AccessToken: "testToken",
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessTokenProvider.CalledWithRefreshToken).To(Equal(mockCache.ReturnToken.RefreshToken))
		Expect(accessToken).To(Equal(accessTokenProvider.ReturnRefreshToken.AccessToken))
	})

	It("when nothing is in the cache", func() {
		mockCache.ReturnToken = nil
		accessTokenProvider.ReturnAuthenticateToken = &TokenResult{
			AccessToken: "testToken",
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessTokenProvider.CalledAuthenticate).To(BeTrue())
		Expect(accessToken).To(Equal(accessTokenProvider.ReturnAuthenticateToken.AccessToken))
	})

	It("authenticates when refresh and access token are empty", func() {
		mockCache.ReturnToken = &TokenResult{}
		accessTokenProvider.ReturnAuthenticateToken = &TokenResult{
			AccessToken: "testToken",
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessTokenProvider.CalledAuthenticate).To(BeTrue())
		Expect(accessToken).To(Equal(accessTokenProvider.ReturnAuthenticateToken.AccessToken))
	})

	It("caches id and refresh tokens after authenticating", func() {
		accessTokenProvider.ReturnAuthenticateToken = &TokenResult{
			AccessToken:  "testToken",
			RefreshToken: "refreshToken",
		}

		ctp.GetAccessToken()

		Expect(mockCache.CachedToken).To(Equal(accessTokenProvider.ReturnAuthenticateToken))
	})

	It("caches the new access token and orig refresh token after refreshing", func() {
		mockCache.ReturnToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Second * -50)),
			RefreshToken: "refreshToken",
		}
		accessTokenProvider.ReturnRefreshToken = &TokenResult{
			AccessToken: "refreshedToken",
		}

		ctp.GetAccessToken()

		Expect(mockCache.CachedToken).To(Equal(&TokenResult{
			AccessToken:  accessTokenProvider.ReturnRefreshToken.AccessToken,
			RefreshToken: mockCache.ReturnToken.RefreshToken,
		}))
	})

	It("passes along an error from authenticate", func() {
		accessTokenProvider.ReturnAuthenticateError = errors.New("someerror")

		accessToken, err := ctp.GetAccessToken()

		Expect(accessToken).To(BeEmpty())
		Expect(err.Error()).To(Equal("someerror"))
	})

	It("passes along an error from caching tokens", func() {
		mockCache.CacheReturnsError = errors.New("uh oh")

		accessToken, err := ctp.GetAccessToken()

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("could not cache tokens: uh oh"))
		Expect(accessToken).To(BeEmpty())
	})

	It("passes along an error from the cache when getting tokens returns an error", func() {
		mockCache.GetReturnsError = errors.New("uh oh")

		accessToken, err := ctp.GetAccessToken()

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("could get tokens from the cache: uh oh"))
		Expect(accessToken).To(BeEmpty())
	})
})
