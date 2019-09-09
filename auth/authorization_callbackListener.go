package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
)

// HTTPServer abstracts the functions needed for starting and shutting down an
// HTTP server
type HTTPServer interface {
	Start(addr string)
	Shutdown()
}

// CallbackService is used to handle the callback received in the PKCE flow
type CallbackService struct {
	addr       string
	httpServer HTTPServer
}

// callbackServer is an implementation of HTTPServer
type callbackServer struct {
	server *http.Server
}

// Start starts the HTTP server
func (s *callbackServer) Start(addr string) {
	s.server = &http.Server{
		Addr: addr,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
			panic(err)
		}
	}()
}

// Shutdown gracefully shuts down the HTTP server
func (s *callbackServer) Shutdown() {
	if err := s.server.Shutdown(context.Background()); err != nil {
		log.Printf("HTTP server Shutdown error: %v", err)
	}
}

// NewLocalCallbackListener creates a new CallbackService with a callbackServer
// that listens on 127.0.0.1
func NewLocalCallbackListener(port int) *CallbackService {
	return NewCallbackListener(fmt.Sprintf("127.0.0.1:%d", port), &callbackServer{})
}

// NewCallbackListener creates a new CallbackService that uses the passed in
// httpServer to listen on the passed in addr
func NewCallbackListener(addr string, httpServer HTTPServer) *CallbackService {
	return &CallbackService{
		addr,
		httpServer,
	}
}

// GetCallbackURL returns the callback url that is used to receive the
// authorization code
func (c *CallbackService) GetCallbackURL() string {
	return fmt.Sprintf("http://%s/callback", c.addr)
}

// BuildCodeResponseHandler builds the HTTP handler func that receives the
// authorization code callback
func (c *CallbackService) BuildCodeResponseHandler(responseC chan CallbackResponse, state string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		response := CallbackResponse{}

		if r.URL.Query().Get("state") != state {
			response.Error = errors.New("callback completed with incorrect state")
			w.Write([]byte("An error occurred. Please check terminal for output."))
		} else if callbackErr := r.URL.Query().Get("error"); callbackErr != "" {
			response.Error = fmt.Errorf("%s: %s", callbackErr, r.URL.Query().Get("error_description"))
			w.Write([]byte("An error occurred. Please check terminal for output."))
		} else if code := r.URL.Query().Get("code"); code != "" {
			response.Code = code
			w.Write([]byte("You've been authorized and may now close this browser page."))
		} else {
			response.Error = errors.New("callback completed with no error or code")
			w.Write([]byte("An error occurred. Please check terminal for output."))
		}

		responseC <- response
	}
}

// Close tells the HTTP server to gracefully shutdown
func (c *CallbackService) Close() {
	c.httpServer.Shutdown()
}

// AwaitResponse sets up the response channel to receive the code that comes in
// the from authorizatino code callback handler
func (c *CallbackService) AwaitResponse(response chan CallbackResponse, state string) {
	c.httpServer.Start(c.addr)
	http.HandleFunc("/callback", c.BuildCodeResponseHandler(response, state))
}
