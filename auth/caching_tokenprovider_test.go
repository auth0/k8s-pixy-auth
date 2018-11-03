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

type inMemoryCachingProvider struct {
	ReturnToken *TokenResult
	CachedToken *TokenResult
}

func (i *inMemoryCachingProvider) GetTokens() *TokenResult {
	return i.ReturnToken
}

func (i *inMemoryCachingProvider) CacheTokens(toCache *TokenResult) {
	i.CachedToken = toCache
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
	var inMemCache *inMemoryCachingProvider
	var accessTokenProvider *mockTokenProvider
	var ctp CachingTokenProvider

	BeforeEach(func() {
		inMemCache = &inMemoryCachingProvider{}
		accessTokenProvider = &mockTokenProvider{}
		ctp = CachingTokenProvider{
			cache:               inMemCache,
			accessTokenProvider: accessTokenProvider,
		}
	})

	It("returns an access token from the cache", func() {
		inMemCache.ReturnToken = &TokenResult{
			AccessToken: genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessToken).To(Equal(inMemCache.ReturnToken.AccessToken))
	})

	It("refreshes token when access token is invalid", func() {
		accessTokenProvider.ReturnRefreshToken = &TokenResult{
			AccessToken: "testToken",
		}
		inMemCache.ReturnToken = &TokenResult{
			RefreshToken: "refreshToken",
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessTokenProvider.CalledWithRefreshToken).To(Equal(inMemCache.ReturnToken.RefreshToken))
		Expect(accessToken).To(Equal(accessTokenProvider.ReturnRefreshToken.AccessToken))
	})

	It("runs a full authentication if refresh returns an error", func() {
		inMemCache.ReturnToken = &TokenResult{
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
		inMemCache.ReturnToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Second * -50)),
			RefreshToken: "refreshToken",
		}
		accessTokenProvider.ReturnRefreshToken = &TokenResult{
			AccessToken: "testToken",
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessTokenProvider.CalledWithRefreshToken).To(Equal(inMemCache.ReturnToken.RefreshToken))
		Expect(accessToken).To(Equal(accessTokenProvider.ReturnRefreshToken.AccessToken))
	})

	It("when nothing is in the cache", func() {
		inMemCache.ReturnToken = nil
		accessTokenProvider.ReturnAuthenticateToken = &TokenResult{
			AccessToken: "testToken",
		}

		accessToken, _ := ctp.GetAccessToken()

		Expect(accessTokenProvider.CalledAuthenticate).To(BeTrue())
		Expect(accessToken).To(Equal(accessTokenProvider.ReturnAuthenticateToken.AccessToken))
	})

	It("authenticates when refresh and access token are empty", func() {
		inMemCache.ReturnToken = &TokenResult{}
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

		Expect(inMemCache.CachedToken).To(Equal(accessTokenProvider.ReturnAuthenticateToken))
	})

	It("caches the new access token and orig refresh token after refreshing", func() {
		inMemCache.ReturnToken = &TokenResult{
			AccessToken:  genValidTokenWithExp(time.Now().Add(time.Second * -50)),
			RefreshToken: "refreshToken",
		}
		accessTokenProvider.ReturnRefreshToken = &TokenResult{
			AccessToken: "refreshedToken",
		}

		ctp.GetAccessToken()

		Expect(inMemCache.CachedToken).To(Equal(&TokenResult{
			AccessToken:  accessTokenProvider.ReturnRefreshToken.AccessToken,
			RefreshToken: inMemCache.ReturnToken.RefreshToken,
		}))
	})

	It("passes along an error from authenticate", func() {
		accessTokenProvider.ReturnAuthenticateError = errors.New("someerror")

		accessToken, err := ctp.GetAccessToken()

		Expect(accessToken).To(BeEmpty())
		Expect(err.Error()).To(Equal("someerror"))
	})
})
