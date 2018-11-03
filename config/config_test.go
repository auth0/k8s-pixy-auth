package config

import (
	"bytes"
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
)

func TestAuth0KubectlAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../test-results/junit/config.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Auth0KubectlAuth Config Suite", []Reporter{junitReporter})
}

var _ = Describe("Config", func() {
	Context("with valid yaml", func() {
		testYaml := `
clients:
  testing:
    accessToken: testing_AccessToken
    refreshToken: testing_refreshToken
`
		buffer := bytes.NewBufferString(testYaml)
		config := NewConfig(buffer)

		It("gets tokens when present", func() {
			AccessToken, refreshToken := config.GetTokens("testing")

			Expect(AccessToken).To(Equal("testing_AccessToken"))
			Expect(refreshToken).To(Equal("testing_refreshToken"))
		})

		It("returns empty when no tokens are present for client", func() {
			AccessToken, refreshToken := config.GetTokens("not_present")

			Expect(AccessToken).To(BeEmpty())
			Expect(refreshToken).To(BeEmpty())
		})

		It("save should overwrite old tokens", func() {
			updatedYaml := `clients:
  testing:
    accessToken: newAccessToken
    refreshToken: newRefreshToken
`
			config.SaveTokens("testing", "newAccessToken", "newRefreshToken")

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
