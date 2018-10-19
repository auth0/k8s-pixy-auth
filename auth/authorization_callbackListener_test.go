package auth

import (
	"errors"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type MockHttpServer struct {
	StartCalled, ShutdownCalled bool
	httpRecorder                *httptest.ResponseRecorder
}

func (s *MockHttpServer) Start(addr string) {
	s.StartCalled = true
}

func (s *MockHttpServer) Shutdown() {
	s.ShutdownCalled = true
}

var _ = Describe("AuthCallbackService", func() {
	var mockHTTP *MockHttpServer

	BeforeEach(func() {
		mockHTTP = &MockHttpServer{
			StartCalled:    false,
			ShutdownCalled: false,
			httpRecorder:   httptest.NewRecorder(),
		}
	})
	It("starts the server", func() {
		server := NewCallbackListener("testing:1234", mockHTTP)

		resp := make(chan CallbackResponse)
		defer close(resp)

		server.AwaitResponse(resp)

		Expect(mockHTTP.StartCalled).To(BeTrue())
	})

	It("returns the code after callback", func() {
		server := NewCallbackListener("testing:1234", mockHTTP)

		resp := make(chan CallbackResponse)
		defer close(resp)

		req := httptest.NewRequest("GET", "/callback?code=1234", nil)

		go server.BuildCodeResponseHandler(resp)(mockHTTP.httpRecorder, req)

		Expect(<-resp).To(Equal(CallbackResponse{Code: "1234"}))
	})

	It("returns the correct callback url for the listener", func() {
		server := NewCallbackListener("testing:1234", mockHTTP)

		callbackURL := server.GetCallbackURL()

		Expect(callbackURL).To(Equal("http://testing:1234/callback"))
	})

	It("returns an error if error is in the callback url", func() {
		server := NewCallbackListener("testing:1234", mockHTTP)

		resp := make(chan CallbackResponse)
		defer close(resp)

		req := httptest.NewRequest("GET", "/callback?error=uh_oh&error_description=something%20went%20wrong", nil)

		go server.BuildCodeResponseHandler(resp)(mockHTTP.httpRecorder, req)

		Expect(<-resp).To(Equal(CallbackResponse{Error: errors.New("uh_oh: something went wrong")}))
	})

	It("returns an error if no error or code is in the callback url", func() {
		server := NewCallbackListener("testing:1234", mockHTTP)

		resp := make(chan CallbackResponse)
		defer close(resp)

		req := httptest.NewRequest("GET", "/callback", nil)

		go server.BuildCodeResponseHandler(resp)(mockHTTP.httpRecorder, req)

		Expect(<-resp).To(Equal(CallbackResponse{Error: errors.New("callback completed with no error or code")}))
	})

	It("sets up the callback server to listen on localhost", func() {
		l := NewLocalhostCallbackListener(1573)

		Expect(l.addr).To(Equal("localhost:1573"))
	})

	// It("shuts down after wait time")
	// It("shuts down and errors if called back with no code")
})
