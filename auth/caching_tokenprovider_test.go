package auth

import (
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
}

func (i *inMemoryCachingProvider) GetTokens() (*TokenResult, error) {
	return i.ReturnToken, nil
}

type mockTokenProvider struct {
	ReturnToken            *TokenResult
	CalledWithRefreshToken string
}

func (m *mockTokenProvider) FromRefreshToken(refreshToken string) (*TokenResult, error) {
	m.CalledWithRefreshToken = refreshToken
	return m.ReturnToken, nil
}

var _ = Describe("cachingTokenProvider", func() {
	var inMemCache *inMemoryCachingProvider
	var idTokenProvider *mockTokenProvider
	var ctp cachingTokenProvider

	BeforeEach(func() {
		inMemCache = &inMemoryCachingProvider{}
		idTokenProvider = &mockTokenProvider{}
		ctp = cachingTokenProvider{
			cache:           inMemCache,
			idTokenProvider: idTokenProvider,
		}
	})

	It("returns an id token from the cache", func() {
		inMemCache.ReturnToken = &TokenResult{
			IDToken: genValidTokenWithExp(time.Now()),
		}

		idToken := ctp.GetIDToken()

		Expect(idToken).To(Equal(inMemCache.ReturnToken.IDToken))
	})

	It("refreshes token when id token is invalid", func() {
		idTokenProvider.ReturnToken = &TokenResult{
			IDToken: "testToken",
		}
		inMemCache.ReturnToken = &TokenResult{
			RefreshToken: "refreshToken",
		}

		idToken := ctp.GetIDToken()

		Expect(idTokenProvider.CalledWithRefreshToken).To(Equal(inMemCache.ReturnToken.RefreshToken))
		Expect(idToken).To(Equal(idTokenProvider.ReturnToken.IDToken))
	})

	// when the tokenResult is nil

	// when the IDToken is not a valid JWT

	// It("refreshes token when id token is expired", func() {
	// })

	// It("caches new id token after refreshing it", func() {
	// })

	// ignores errors when interacting with cache

	// get a new id token along with a refresh token and cache them
	// propogates errors
})
