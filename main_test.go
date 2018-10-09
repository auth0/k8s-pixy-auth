package main_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/auth0/auth0-client-go-exec-plugin"
)

var _ = Describe("Main", func() {
	Describe("Config", func() {
		Context("yaml", func() {
			It("gets tokens when present", func() {
				testYaml := `
clients:
  testing:
    idToken: testing_idToken
    refreshToken: testing_refreshToken
`
				config := NewConfig(strings.NewReader(testYaml))
				idToken, refreshToken := config.GetTokens("testing")

				Expect(idToken).To(Equal("testing_idToken"))
				Expect(refreshToken).To(Equal("testing_refreshToken"))
			})

			// It("returns empty when no tokens are present for client", func() {

			// })
		})

		// invalid yaml

		// caching yaml
	})
})
