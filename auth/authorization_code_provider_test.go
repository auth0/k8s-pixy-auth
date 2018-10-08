package auth

import (
	"errors"
	"net/url"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockCallbackListener struct {
	responseChannel chan CallbackResponse
	responseChReady chan bool
	CalledWithState string
	AwaitCalled     bool
	ListenURL       string
	CloseCalled     bool
}

func newMockCallbackListener() *mockCallbackListener {
	return &mockCallbackListener{
		responseChReady: make(chan bool),
		ListenURL:       "https://callback",
	}
}

func (cb *mockCallbackListener) CompleteCallback(resp CallbackResponse) {
	// This servesto syncrhonize on when the response channel from AwaitResponse
	// is ready. This is helpful in the tests as we can put the CompleteCallback
	// inside the go func()... and keep our asserts at the end of the tests.
	// Otherwise, you would require to potentially use the ginkgo func(done Done)
	// pattern
	<-cb.responseChReady
	cb.responseChannel <- resp
}

func (cb *mockCallbackListener) AwaitResponse(resp chan CallbackResponse, state string) {
	cb.AwaitCalled = true
	cb.CalledWithState = state
	cb.responseChannel = resp
	cb.responseChReady <- true
}

func (cb *mockCallbackListener) GetCallbackURL() string {
	return cb.ListenURL
}

func (cb *mockCallbackListener) Close() {
	cb.CloseCalled = true
}

type mockInteractor struct {
	URL          string
	ReturnsError error
}

func (i *mockInteractor) OpenURL(url string) error {
	i.URL = url
	return i.ReturnsError
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

	stateResult := "randomstring1234"
	mockState := func() string { return stateResult }

	It("waits for a response from the callback", func(done Done) {
		mockListener := newMockCallbackListener()
		provider := NewLocalhostCodeProvider(
			issuerData,
			mockListener,
			&mockInteractor{},
			mockState,
		)
		go provider.GetCode(challenge)

		mockListener.CompleteCallback(CallbackResponse{})
		Expect(mockListener.AwaitCalled).To(BeTrue())
		Expect(mockListener.CalledWithState).To(Equal(stateResult))
		close(done)
	})

	It("closes the listener after receiving the code", func() {
		mockListener := newMockCallbackListener()
		provider := NewLocalhostCodeProvider(
			issuerData,
			mockListener,
			&mockInteractor{},
			mockState,
		)
		go mockListener.CompleteCallback(CallbackResponse{})

		provider.GetCode(challenge)

		Expect(mockListener.CloseCalled).To(BeTrue())
	})

	It("opens the URL with expected auth params", func() {
		mockListener := newMockCallbackListener()
		mockOSInteractor := &mockInteractor{}
		provider := NewLocalhostCodeProvider(
			issuerData,
			mockListener,
			mockOSInteractor,
			mockState,
		)

		go mockListener.CompleteCallback(CallbackResponse{})

		provider.GetCode(challenge)

		parsedURL, err := url.Parse(mockOSInteractor.URL)

		Expect(err).To(BeNil())
		Expect(parsedURL.Scheme).To(Equal("https"))
		Expect(parsedURL.Host).To(Equal("issuer"))

		params := parsedURL.Query()
		Expect(len(params)).To(Equal(8))
		Expect(params.Get("state")).To(Equal(stateResult))
		Expect(params.Get("audience")).To(Equal(issuerData.Audience))
		Expect(params.Get("scope")).To(Equal("openid offline_access email"))
		Expect(params.Get("response_type")).To(Equal("code"))
		Expect(params.Get("client_id")).To(Equal(issuerData.ClientID))
		Expect(params.Get("code_challenge")).To(Equal(challenge.Code))
		Expect(params.Get("code_challenge_method")).To(Equal(challenge.Method))
		Expect(params.Get("redirect_uri")).To(Equal(mockListener.GetCallbackURL()))
	})

	It("returns code provided by listener", func() {
		mockListener := newMockCallbackListener()
		provider := NewLocalhostCodeProvider(
			issuerData,
			mockListener,
			&mockInteractor{},
			mockState,
		)

		go mockListener.CompleteCallback(CallbackResponse{Code: "mycode", Error: nil})

		result, _ := provider.GetCode(challenge)
		Expect(result.Code).To(Equal("mycode"))
		Expect(result.RedirectURI).To(Equal(mockListener.GetCallbackURL()))

	})

	It("raises errors if command execution fails", func() {
		mockListener := newMockCallbackListener()
		provider := NewLocalhostCodeProvider(
			issuerData,
			mockListener,
			&mockInteractor{
				ReturnsError: errors.New("someerror"),
			},
			mockState,
		)

		_, err := provider.GetCode(challenge)

		Expect(err.Error()).To(Equal("someerror"))
	})

	It("raises error if listener returns error", func() {
		mockListener := newMockCallbackListener()
		provider := NewLocalhostCodeProvider(
			issuerData,
			mockListener,
			&mockInteractor{},
			mockState,
		)

		go mockListener.CompleteCallback(CallbackResponse{
			Code:  "invalid",
			Error: errors.New("someerror"),
		})

		result, err := provider.GetCode(challenge)

		Expect(result).To(BeNil())
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(Equal("someerror"))
	})
})
