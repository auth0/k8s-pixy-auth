package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
)

type HttpServer interface {
	Start(addr string)
	Shutdown()
}
type CallbackService struct {
	addr       string
	httpServer HttpServer
}

type localhostHttpServer struct {
	server *http.Server
}

func NewLocalhostCallbackListener(port int) *CallbackService {
	return NewCallbackListener(port, &localhostHttpServer{})
}

func NewCallbackListener(port int, httpServer HttpServer) *CallbackService {
	return &CallbackService{
		fmt.Sprintf("localhost:%d", port),
		httpServer,
	}
}

func (c *CallbackService) GetURL() string {
	//todo: this base location should be pulled from server
	return fmt.Sprintf("http://%s/callback", c.addr)
}

func (c *CallbackService) BuildCodeResponseHandler(response chan CallbackResponse) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")

		//TODO: provide errors if code is missing
		response <- CallbackResponse{
			Code:  code,
			Error: nil,
		}

		w.WriteHeader(http.StatusOK)

		//TODO: Defer/delay shutdown offer Close()?
		c.httpServer.Shutdown()
	}
}

func (c *CallbackService) AwaitResponse(response chan CallbackResponse) {
	c.httpServer.Start(c.addr)
	http.HandleFunc("/callback", c.BuildCodeResponseHandler(response))
}

func (s *localhostHttpServer) Start(addr string) {
	//todo: should only ever serve localhost, not any interface (e.g. :0)
	s.server = &http.Server{
		Addr: addr,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
			panic(err)
		}
	}()
}

func (s *localhostHttpServer) Shutdown() {
	if err := s.server.Shutdown(context.Background()); err != nil {
		log.Printf("HTTP server Shutdown error: %v", err)
	}
}
