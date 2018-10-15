package auth_test

import (
	"errors"
	"net/http/httptest"

	. "github.com/auth0/auth0-kubectl-auth/auth"
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
	It("should start server", func() {
		server := NewCallbackListener(1234, mockHTTP)

		resp := make(chan CallbackResponse)
		defer close(resp)

		server.AwaitResponse(resp)

		Expect(mockHTTP.StartCalled).To(BeTrue())
	})

	It("should return code after callback", func(done Done) {
		server := NewCallbackListener(1234, mockHTTP)

		resp := make(chan CallbackResponse)
		defer close(resp)

		req := httptest.NewRequest("GET", "/callback?code=1234", nil)

		go func() {
			server.BuildCodeResponseHandler(resp)(mockHTTP.httpRecorder, req)
		}()

		Expect(<-resp).To(Equal(CallbackResponse{Code: "1234"}))
		close(done)
	})

	It("should shutdown server after callback received", func(done Done) {
		server := NewCallbackListener(1234, mockHTTP)

		resp := make(chan CallbackResponse)
		defer close(resp)

		req := httptest.NewRequest("GET", "/callback?code=1234", nil)

		go func() {
			server.BuildCodeResponseHandler(resp)(mockHTTP.httpRecorder, req)
		}()

		<-resp
		Expect(mockHTTP.ShutdownCalled).To(BeTrue())
		close(done)
	})

	It("returns the correct callback url for the listener", func() {
		server := NewCallbackListener(1234, mockHTTP)

		callbackURL := server.GetCallbackURL()

		Expect(callbackURL).To(Equal("http://localhost:1234/callback"))
	})

	It("returns an error if error is in the callback url", func(done Done) {
		server := NewCallbackListener(1234, mockHTTP)

		resp := make(chan CallbackResponse)
		defer close(resp)

		req := httptest.NewRequest("GET", "/callback?error=uh_oh&error_description=something%20went%20wrong", nil)

		go func() {
			server.BuildCodeResponseHandler(resp)(mockHTTP.httpRecorder, req)
		}()

		Expect(<-resp).To(Equal(CallbackResponse{Error: errors.New("uh_oh: something went wrong")}))
		close(done)
	})

	It("returns an error if no error or code is in the callback url", func(done Done) {
		server := NewCallbackListener(1234, mockHTTP)

		resp := make(chan CallbackResponse)
		defer close(resp)

		req := httptest.NewRequest("GET", "/callback", nil)

		go func() {
			server.BuildCodeResponseHandler(resp)(mockHTTP.httpRecorder, req)
		}()

		Expect(<-resp).To(Equal(CallbackResponse{Error: errors.New("callback completed with no error or code")}))
		close(done)
	})

	// It("should shutdown after wait time")
	// It("should shutdown and error if called back with no code")
})
