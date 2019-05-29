package auth

import (
	"os"

	"github.com/99designs/keyring"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("keyringCachingProvider integration", func() {
	fileDir := "k8s-pixy-auth-testing"
	var passwordFuncCalledWith string
	passwordFuncReturns := "iampassword"
	var p *KeyringCachingProvider
	t := &TokenResult{
		AccessToken:  "asdf",
		RefreshToken: "lkjh",
	}

	BeforeEach(func() {
		passwordFuncCalledWith = ""
	})

	AfterSuite(func() {
		os.RemoveAll(fileDir)
	})

	It("sets up keyring without error", func() {
		k, err := keyring.Open(keyring.Config{
			ServiceName:     "testing",
			AllowedBackends: []keyring.BackendType{keyring.FileBackend},
			FilePasswordFunc: func(prompt string) (string, error) {
				passwordFuncCalledWith = prompt
				return passwordFuncReturns, nil
			},
			FileDir: fileDir,
		})
		Expect(err).NotTo(HaveOccurred())

		p = NewKeyringCachingProvider("clientid", "audience", k)
	})

	It("does not error when getting from keyring and nothing is there", func() {
		r, err := p.GetTokens()

		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(BeNil())

		Expect(passwordFuncCalledWith).To(Equal(""))
	})

	It("successfully stores token results", func() {
		err := p.CacheTokens(t)

		Expect(err).NotTo(HaveOccurred())
		Expect(passwordFuncCalledWith).To(Equal("Enter passphrase to unlock k8s-pixy-auth-testing"))
	})

	It("successfully retrieves token results", func() {
		r, err := p.GetTokens()

		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(Equal(t))

		Expect(passwordFuncCalledWith).To(Equal(""))
	})

	It("errors when the wrong password is sent", func() {
		k, err := keyring.Open(keyring.Config{
			ServiceName:     "testing2",
			AllowedBackends: []keyring.BackendType{keyring.FileBackend},
			FilePasswordFunc: func(prompt string) (string, error) {
				passwordFuncCalledWith = prompt
				return passwordFuncReturns, nil
			},
			FileDir: fileDir,
		})
		Expect(err).NotTo(HaveOccurred())

		p = NewKeyringCachingProvider("clientid", "audience", k)

		passwordFuncReturns = "badpassword"

		r, err := p.GetTokens()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("error getting token information from keyring: aes.KeyUnwrap(): integrity check failed."))
		Expect(r).To(BeNil())
	})
})
