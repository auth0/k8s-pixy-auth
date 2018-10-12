package main

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	Context("with valid yaml", func() {
		testYaml := `
clients:
  testing:
    idToken: testing_idToken
    refreshToken: testing_refreshToken
`
		buffer := bytes.NewBufferString(testYaml)
		config := NewConfig(buffer)

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

		It("cache should overwrite old tokens", func() {
			updatedYaml := `clients:
  testing:
    idToken: newIdToken
    refreshToken: newRefreshToken
`
			config.CacheTokens("testing", "newIdToken", "newRefreshToken")

			Expect(buffer.String()).To(Equal(updatedYaml))
		})
	})

	Context("with invalid yaml", func() {
		It("should panic", func() {
			testYaml := `
clients:
  - testing:
    - testing_id: blah
`
			Expect(func() {
				_ = NewConfig(bytes.NewBufferString(testYaml))
			}).Should(Panic())
		})
	})
})
