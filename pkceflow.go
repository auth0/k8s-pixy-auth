package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
)

type authorizationCodeExchange struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	CodeVerifier string `json:"code_verifier"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
}

type authorizationCodeResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// generateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// generateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
func generateRandomString(s int) (string, error) {
	b, err := generateRandomBytes(s)
	return base64.RawURLEncoding.EncodeToString(b), err
}

// openURL opens the specified URL in the default browser of the user.
func openURL(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

func getCallbackHandler(sendResponseTo chan url.Values) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sendResponseTo <- r.URL.Query()
	}
}

func listenAndServe(server *http.Server) {
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		log.Printf("HTTP server ListenAndServe error: %v", err)
	}
}

func pkceFlow(domain, clientID, audience string) (string, string) {
	responseChan := make(chan url.Values)

	http.HandleFunc("/callback", getCallbackHandler(responseChan))

	s := &http.Server{
		Addr: ":8080",
	}
	go listenAndServe(s)

	verifier, err := generateRandomString(32)
	if err != nil {
		panic(err)
	}

	csum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(csum[:])

	openURL(fmt.Sprintf(
		"https://%v/authorize?audience=%v&scope=openid offline_access email&response_type=code&client_id=%v&code_challenge=%v&code_challenge_method=S256&redirect_uri=http://localhost:8080/callback",
		domain,
		audience,
		clientID,
		challenge))
	queryParams := <-responseChan

	code := queryParams.Get("code")

	if err := s.Shutdown(context.Background()); err != nil {
		// Error from closing listeners, or context timeout:
		log.Printf("HTTP server Shutdown error: %v", err)
	}

	codeExchange := authorizationCodeExchange{
		GrantType:    "authorization_code",
		ClientID:     clientID,
		CodeVerifier: verifier,
		Code:         code,
		RedirectURI:  "http://localhost:8080/callback",
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(codeExchange)

	resp, err := http.Post(fmt.Sprintf("https://%v/oauth/token", domain), "application/json", b)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	acr := authorizationCodeResponse{}
	err = json.NewDecoder(resp.Body).Decode(&acr)
	if err != nil {
		panic(err)
	}

	return acr.IDToken, acr.RefreshToken
}
