package main_test

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/auth0/auth0-k8s-client-go-exec-plugin"
)

var _ = Describe("Main", func() {
	Describe("Config", func() {
		Context("yaml", func() {
			testYaml := `
clients:
  testing:
    idToken: testing_idToken
    refreshToken: testing_refreshToken
`
			config := NewConfig(bytes.NewBufferString(testYaml))

			It("gets tokens when present", func() {
				idToken, refreshToken := config.GetTokens("testing")

				Expect(idToken).To(Equal("testing_idToken"))
				Expect(refreshToken).To(Equal("testing_refreshToken"))
			})

			It("returns empty when no tokens are present for client", func() {
				idToken, refreshToken := config.GetTokens("not_present")

				Expect(idToken).To(BeEmpty())
				Expect(refreshToken).To(BeEmpty())
			})
		})

		// invalid yaml

		// caching yaml
	})
})
