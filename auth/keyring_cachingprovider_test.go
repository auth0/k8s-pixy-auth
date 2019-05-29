package auth

import (
	"github.com/99designs/keyring"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
)

type mockKeyringProvider struct {
	GetCalledWith   string
	GetReturnsItem  keyring.Item
	GetReturnsError error

	SetCalledWith   keyring.Item
	SetReturnsError error
}

func (mkp *mockKeyringProvider) Get(key string) (keyring.Item, error) {
	mkp.GetCalledWith = key
	return mkp.GetReturnsItem, mkp.GetReturnsError
}

func (mkp *mockKeyringProvider) Set(item keyring.Item) error {
	mkp.SetCalledWith = item
	return mkp.SetReturnsError
}

type mockMarshalToJSON struct {
	CalledWith   interface{}
	ReturnsError error
}

func (mmtj *mockMarshalToJSON) MarshalToJSON(i interface{}) ([]byte, error) {
	mmtj.CalledWith = i
	return nil, mmtj.ReturnsError
}

var _ = Describe("keyringCachingProvider", func() {
	Describe("marshalToJSON", func() {
		It("errors when marshalling errors", func() {
			_, err := marshalToJSON(func() {})

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("could not marshal to json: json: unsupported type: func()"))
		})
	})

	It("sets up the identifier using the clientID and audience", func() {
		p := NewKeyringCachingProvider("iamclientid", "iamaudience", &mockKeyringProvider{})

		Expect(p.identifier).To(Equal("iamclientid-iamaudience"))
	})

	It("gets tokens from the keyring provider", func() {
		k := &mockKeyringProvider{
			GetReturnsItem: keyring.Item{
				Data: []byte(`{"access_token":"asdf","refresh_token":"lkjh"}`),
			},
		}
		p := NewKeyringCachingProvider("clientid", "audience", k)

		r, err := p.GetTokens()

		Expect(err).NotTo(HaveOccurred())
		Expect(k.GetCalledWith).To(Equal(p.identifier))
		Expect(r).To(Equal(&TokenResult{
			AccessToken:  "asdf",
			RefreshToken: "lkjh",
		}))
	})

	It("returns errors from getting the token from keyring", func() {
		k := &mockKeyringProvider{
			GetReturnsError: errors.New("uh oh"),
		}
		p := NewKeyringCachingProvider("clientid", "audience", k)

		r, err := p.GetTokens()

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("error getting token information from keyring: uh oh"))
		Expect(k.GetCalledWith).To(Equal(p.identifier))
		Expect(r).To(BeNil())
	})

	It("does not return an error when nothing can be found", func() {
		k := &mockKeyringProvider{
			GetReturnsError: keyring.ErrKeyNotFound,
		}
		p := NewKeyringCachingProvider("clientid", "audience", k)

		r, err := p.GetTokens()

		Expect(err).NotTo(HaveOccurred())
		Expect(k.GetCalledWith).To(Equal(p.identifier))
		Expect(r).To(BeNil())
	})

	It("returns errors from unmarshalling the token result", func() {
		k := &mockKeyringProvider{
			GetReturnsItem: keyring.Item{
				Data: []byte("<>"),
			},
		}
		p := NewKeyringCachingProvider("clientid", "audience", k)

		r, err := p.GetTokens()

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("could not unmarshal token data from keyring: invalid character '<' looking for beginning of value"))
		Expect(k.GetCalledWith).To(Equal(p.identifier))
		Expect(r).To(BeNil())
	})

	It("stores tokens in the secure provider", func() {
		k := &mockKeyringProvider{}
		p := NewKeyringCachingProvider("clientid", "audience", k)

		err := p.CacheTokens(&TokenResult{
			AccessToken:  "asdf",
			RefreshToken: "lkjh",
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(k.SetCalledWith).To(Equal(keyring.Item{
			Key:  p.identifier,
			Data: []byte(`{"access_token":"asdf","refresh_token":"lkjh","expires_in":0}`),
		}))
	})

	It("returns errors from marshaling the token result to json", func() {
		k := &mockKeyringProvider{}
		mmtj := mockMarshalToJSON{
			ReturnsError: errors.New("uh oh"),
		}

		p := NewKeyringCachingProvider("clientid", "audience", k)
		p.marshalToJSON = mmtj.MarshalToJSON

		err := p.CacheTokens(&TokenResult{
			AccessToken:  "asdf",
			RefreshToken: "lkjh",
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("could not marshal token data for caching in keyring: uh oh"))
		Expect(mmtj.CalledWith).To(Equal(&TokenResult{
			AccessToken:  "asdf",
			RefreshToken: "lkjh",
		}))
	})

	It("returns errors from setting the token in keyring", func() {
		k := &mockKeyringProvider{
			SetReturnsError: errors.New("uh oh"),
		}
		p := NewKeyringCachingProvider("clientid", "audience", k)

		err := p.CacheTokens(&TokenResult{
			AccessToken:  "asdf",
			RefreshToken: "lkjh",
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("error setting token information in keyring: uh oh"))
		Expect(k.SetCalledWith).To(Equal(keyring.Item{
			Key:  p.identifier,
			Data: []byte(`{"access_token":"asdf","refresh_token":"lkjh","expires_in":0}`),
		}))
	})
})
