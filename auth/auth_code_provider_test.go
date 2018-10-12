package auth_test

import (
	"net/url"

	. "github.com/auth0/auth0-kubectl-auth/auth"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockCallbackListener struct {
	responseChannel chan CallbackResponse
	responseChReady chan bool
	AwaitCalled     bool
	ListenURL       string
}

func newMockCallbackListener() *mockCallbackListener {
	return &mockCallbackListener{
		responseChReady: make(chan bool),
		ListenURL:       "https://callback",
	}
}

func (cb *mockCallbackListener) CompleteCallback(resp CallbackResponse) {
	<-cb.responseChReady
	cb.responseChannel <- resp
}

func (cb *mockCallbackListener) AwaitResponse(resp chan CallbackResponse) {
	cb.AwaitCalled = true
	cb.responseChannel = resp
	cb.responseChReady <- true
}

func (cb *mockCallbackListener) GetURL() string {
	return cb.ListenURL
}

type mockInteractor struct {
	Url string
}

func newMockOSInteractor() *mockInteractor {
	return &mockInteractor{}
}

func (i *mockInteractor) OpenURL(url string) error {
	i.Url = url
	return nil
}

var _ = Describe("AuthCodeProvider", func() {
	issuerData := Issuer{
		IssuerEndpoint: "https://issuer",
		ClientID:       "test_clientID",
		Audience:       "test_audience",
	}

	challenge := Challenge{
		Code:     "ABC123",
		Verifier: "VERIFY",
		Method:   "SHA",
	}

	It("Should wait response from callback", func(done Done) {
		mockListener := newMockCallbackListener()
		provider := NewAuthCodeProvider(
			issuerData,
			mockListener,
			newMockOSInteractor(),
		)
		go func() {
			_ = provider.GetCode(challenge)
		}()

		mockListener.CompleteCallback(CallbackResponse{})
		Expect(mockListener.AwaitCalled).To(BeTrue())
		close(done)
	})

	It("should open URL with expected auth params", func(done Done) {
		mockListener := newMockCallbackListener()
		mockOSInteractor := newMockOSInteractor()
		provider := NewAuthCodeProvider(
			issuerData,
			mockListener,
			mockOSInteractor,
		)
		go func() {
			_ = provider.GetCode(challenge)
		}()

		mockListener.CompleteCallback(CallbackResponse{})

		parsedURL, err := url.Parse(mockOSInteractor.Url)

		Expect(err).To(BeNil())
		Expect(parsedURL.Scheme).To(Equal("https"))
		Expect(parsedURL.Host).To(Equal("issuer"))

		params := parsedURL.Query()
		Expect(len(params)).To(Equal(7))
		Expect(params.Get("audience")).To(Equal(issuerData.Audience))
		Expect(params.Get("scope")).To(Equal("openid offline_access email"))
		Expect(params.Get("response_type")).To(Equal("code"))
		Expect(params.Get("client_id")).To(Equal(issuerData.ClientID))
		Expect(params.Get("code_challenge")).To(Equal(challenge.Code))
		Expect(params.Get("code_challenge_method")).To(Equal(challenge.Method))
		Expect(params.Get("redirect_uri")).To(Equal(mockListener.GetURL()))
		close(done)
	})

	It("Returns code provided by listener", func(done Done) {
		var result AuthCodeResult
		mockListener := newMockCallbackListener()
		mockOSInteractor := newMockOSInteractor()
		provider := NewAuthCodeProvider(
			issuerData,
			mockListener,
			mockOSInteractor,
		)

		go func() {
			result = provider.GetCode(challenge)
			Expect(result.Code).To(Equal("mycode"))
			Expect(result.RedirectURI).To(Equal(mockListener.GetURL()))
			close(done)
		}()

		mockListener.CompleteCallback(CallbackResponse{Code: "mycode", Error: nil})
	})

	//TODO: Errors from code provider?
})
