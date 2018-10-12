package auth_test

import (
	"net/http/httptest"

	. "github.com/auth0/auth0-kubectl-auth/auth"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type MockHttpServer struct {
	StartCalled, ShutdownCalled bool
	httpRecorder                *httptest.ResponseRecorder
}

func (s *MockHttpServer) Start(port int) {
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

	// It("should shutdown after wait time")
	// It("should shutdown and error if called back with no code")
})
