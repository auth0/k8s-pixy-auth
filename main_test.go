package main

import (
	"github.com/auth0/auth0-kubectl-auth/auth"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockConfigProvider struct {
	ReturnIDToken             string
	ReturnRefreshToken        string
	GetTokensCalledIdentifier string
	SavedIdentifier           string
	SavedIDToken              string
	SavedRefreshToken         string
}

func (m *mockConfigProvider) GetTokens(identifier string) (string, string) {
	m.GetTokensCalledIdentifier = identifier
	return m.ReturnIDToken, m.ReturnRefreshToken
}

func (m *mockConfigProvider) SaveTokens(identifier, idToken, refreshToken string) {
	m.SavedIdentifier = identifier
	m.SavedIDToken = idToken
	m.SavedRefreshToken = refreshToken
}

var _ = Describe("main", func() {
	Describe("configCachingProvider", func() {
		It("sets up the identifier using the clientID and audience", func() {
			p := newConfigBackedCachingProvider("iamclientid", "iamaudience", &mockConfigProvider{})

			Expect(p.identifier).To(Equal("iamclientid-iamaudience"))
		})

		It("gets tokens from the config provider", func() {
			c := &mockConfigProvider{
				ReturnIDToken:      "idToken",
				ReturnRefreshToken: "refreshToken",
			}
			p := configBackedCachingProvider{
				identifier: "iamidentifier",
				config:     c,
			}

			r := p.GetTokens()

			Expect(c.GetTokensCalledIdentifier).To(Equal(p.identifier))
			Expect(r).To(Equal(&auth.TokenResult{
				IDToken:      c.ReturnIDToken,
				RefreshToken: c.ReturnRefreshToken,
			}))
		})

		It("caches the tokens in the config provider", func() {
			c := &mockConfigProvider{}
			p := configBackedCachingProvider{
				identifier: "iamidentifier",
				config:     c,
			}
			toSave := &auth.TokenResult{
				IDToken:      "idToken",
				RefreshToken: "refreshToken",
			}

			p.CacheTokens(toSave)

			Expect(c.SavedIdentifier).To(Equal(p.identifier))
			Expect(c.SavedIDToken).To(Equal(toSave.IDToken))
			Expect(c.SavedRefreshToken).To(Equal(toSave.RefreshToken))
		})
	})
})
