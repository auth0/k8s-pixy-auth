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
	var idTokenProvider *mockTokenProvider
	var ctp CachingTokenProvider

	BeforeEach(func() {
		inMemCache = &inMemoryCachingProvider{}
		idTokenProvider = &mockTokenProvider{}
		ctp = CachingTokenProvider{
			cache:           inMemCache,
			idTokenProvider: idTokenProvider,
		}
	})

	It("returns an id token from the cache", func() {
		inMemCache.ReturnToken = &TokenResult{
			IDToken: genValidTokenWithExp(time.Now().Add(time.Minute * 2)),
		}

		idToken, _ := ctp.GetIDToken()

		Expect(idToken).To(Equal(inMemCache.ReturnToken.IDToken))
	})

	It("refreshes token when id token is invalid", func() {
		idTokenProvider.ReturnRefreshToken = &TokenResult{
			IDToken: "testToken",
		}
		inMemCache.ReturnToken = &TokenResult{
			RefreshToken: "refreshToken",
		}

		idToken, _ := ctp.GetIDToken()

		Expect(idTokenProvider.CalledWithRefreshToken).To(Equal(inMemCache.ReturnToken.RefreshToken))
		Expect(idToken).To(Equal(idTokenProvider.ReturnRefreshToken.IDToken))
	})

	It("runs a full authentication if refresh returns an error", func() {
		inMemCache.ReturnToken = &TokenResult{
			RefreshToken: "refreshToken",
		}
		idTokenProvider.ReturnRefreshError = errors.New("someerror")
		idTokenProvider.ReturnAuthenticateToken = &TokenResult{
			IDToken: "testToken",
		}

		idToken, _ := ctp.GetIDToken()

		Expect(idTokenProvider.CalledAuthenticate).To(BeTrue())
		Expect(idToken).To(Equal(idTokenProvider.ReturnAuthenticateToken.IDToken))
	})

	It("refreshes token when id token is expired", func() {
		inMemCache.ReturnToken = &TokenResult{
			IDToken:      genValidTokenWithExp(time.Now().Add(time.Second * -50)),
			RefreshToken: "refreshToken",
		}
		idTokenProvider.ReturnRefreshToken = &TokenResult{
			IDToken: "testToken",
		}

		idToken, _ := ctp.GetIDToken()

		Expect(idTokenProvider.CalledWithRefreshToken).To(Equal(inMemCache.ReturnToken.RefreshToken))
		Expect(idToken).To(Equal(idTokenProvider.ReturnRefreshToken.IDToken))
	})

	It("when nothing is in the cache", func() {
		inMemCache.ReturnToken = nil
		idTokenProvider.ReturnAuthenticateToken = &TokenResult{
			IDToken: "testToken",
		}

		idToken, _ := ctp.GetIDToken()

		Expect(idTokenProvider.CalledAuthenticate).To(BeTrue())
		Expect(idToken).To(Equal(idTokenProvider.ReturnAuthenticateToken.IDToken))
	})

	It("authenticates when refresh and id token are empty", func() {
		inMemCache.ReturnToken = &TokenResult{}
		idTokenProvider.ReturnAuthenticateToken = &TokenResult{
			IDToken: "testToken",
		}

		idToken, _ := ctp.GetIDToken()

		Expect(idTokenProvider.CalledAuthenticate).To(BeTrue())
		Expect(idToken).To(Equal(idTokenProvider.ReturnAuthenticateToken.IDToken))
	})

	It("caches id and refresh tokens after authenticating", func() {
		idTokenProvider.ReturnAuthenticateToken = &TokenResult{
			IDToken:      "testToken",
			RefreshToken: "refreshToken",
		}

		ctp.GetIDToken()

		Expect(inMemCache.CachedToken).To(Equal(idTokenProvider.ReturnAuthenticateToken))
	})

	It("caches the new id token and orig refresh token after refreshing", func() {
		inMemCache.ReturnToken = &TokenResult{
			IDToken:      genValidTokenWithExp(time.Now().Add(time.Second * -50)),
			RefreshToken: "refreshToken",
		}
		idTokenProvider.ReturnRefreshToken = &TokenResult{
			IDToken: "refreshedToken",
		}

		ctp.GetIDToken()

		Expect(inMemCache.CachedToken).To(Equal(&TokenResult{
			IDToken:      idTokenProvider.ReturnRefreshToken.IDToken,
			RefreshToken: inMemCache.ReturnToken.RefreshToken,
		}))
	})

	It("passes along an error from authenticate", func() {
		idTokenProvider.ReturnAuthenticateError = errors.New("someerror")

		idToken, err := ctp.GetIDToken()

		Expect(idToken).To(BeEmpty())
		Expect(err.Error()).To(Equal("someerror"))
	})
})
