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

// TODO: nothing makes this a localhost specifc HTTP server unless it actual
// sets up the server addr to have `localhost:` at the beginning. We should
// either change the name of this or change how it sets the addr

// localhostHTTPServer is an implementation of HTTPServer for localhost
type localhostHTTPServer struct {
	server *http.Server
}

// Start starts the HTTP server
func (s *localhostHTTPServer) Start(addr string) {
	s.server = &http.Server{
		Addr: addr,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
			panic(err)
		}
	}()
}

// Shutdown gracefully shutsdown the HTTP server
func (s *localhostHTTPServer) Shutdown() {
	if err := s.server.Shutdown(context.Background()); err != nil {
		log.Printf("HTTP server Shutdown error: %v", err)
	}
}

// NewLocalhostCallbackListener creates a new CallbackService with a localhostHTTPServer
func NewLocalhostCallbackListener(port int) *CallbackService {
	return NewCallbackListener(port, &localhostHTTPServer{})
}

// NewCallbackListener creates a new CallbackService that uses the passed in
// httpServer to listen on the passed in port
func NewCallbackListener(port int, httpServer HTTPServer) *CallbackService {
	return &CallbackService{
		fmt.Sprintf("localhost:%d", port),
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
func (c *CallbackService) BuildCodeResponseHandler(responseC chan CallbackResponse) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		response := CallbackResponse{}

		callbackErr := r.URL.Query().Get("error")

		if callbackErr != "" {
			response.Error = fmt.Errorf("%s: %s", callbackErr, r.URL.Query().Get("error_description"))
			w.Write([]byte("An error occured. Please check terminal for output."))
		} else if code := r.URL.Query().Get("code"); code != "" {
			response.Code = code
			w.Write([]byte("You've been authorized and may now close this browser page."))
		} else {
			response.Error = errors.New("callback completed with no error or code")
			w.Write([]byte("An error occured. Please check terminal for output."))
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
func (c *CallbackService) AwaitResponse(response chan CallbackResponse) {
	c.httpServer.Start(c.addr)
	http.HandleFunc("/callback", c.BuildCodeResponseHandler(response))
}
