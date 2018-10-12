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

// generateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
func generateRandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
}

// authorizationCodeFlowHelper handles listening for the authorization code
// callback as well as opening the URL that will result in the code being sent
// to the callback
type authorizationCodeFlowHelper interface {
	InitCallbackListener(port int) chan string
	OpenURL(string) error
	GetCallbackURL() string
}

// getAuthorizationCode gets the authorization code needed for getting an id
// and refresh token
func getAuthorizationCode(issuer, clientID, audience, challenge, challengeMethod string, helper authorizationCodeFlowHelper) string {
	codeChan := helper.InitCallbackListener(28840)

	helper.OpenURL(fmt.Sprintf(
		"%s/authorize?audience=%s&scope=openid offline_access email&response_type=code&client_id=%s&code_challenge=%s&code_challenge_method=%s&redirect_uri=%s",
		issuer,
		audience,
		clientID,
		challenge,
		challengeMethod,
		helper.GetCallbackURL(),
	))

	return <-codeChan
}

type getAuthorizationCodeFlowHelper struct {
	callbackURL string
}

func (g *getAuthorizationCodeFlowHelper) InitCallbackListener(port int) chan string {
	responseChan := make(chan string)

	go func() {
		done := make(chan bool)
		http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
			responseChan <- r.URL.Query().Get("code")
			done <- true
		})

		s := &http.Server{
			Addr: fmt.Sprintf(":%d", port),
		}
		go func() {
			if err := s.ListenAndServe(); err != http.ErrServerClosed {
				log.Printf("HTTP server ListenAndServe error: %v", err)
			}
		}()

		<-done

		if err := s.Shutdown(context.Background()); err != nil {
			log.Printf("HTTP server Shutdown error: %v", err)
		}

	}()

	g.callbackURL = fmt.Sprintf("http://localhost:%d/callback", port)

	return responseChan
}

func (g getAuthorizationCodeFlowHelper) OpenURL(url string) error {
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

func (g *getAuthorizationCodeFlowHelper) GetCallbackURL() string {
	return g.callbackURL
}

// exchangeAuthorizationCodeForIDAndRefreshToken exchanges an authorization code
// for an id and refresh token
func exchangeAuthorizationCodeForIDAndRefreshToken(issuer, clientID, verifier, code, redirectURI string, exchanger httpTokenExchanger) (string, string) {
	codeExchange := authorizationCodeExchange{
		GrantType:    "authorization_code",
		ClientID:     clientID,
		CodeVerifier: verifier,
		Code:         code,
		RedirectURI:  redirectURI,
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(codeExchange)

	resp, err := exchanger.Post(fmt.Sprintf("%v/oauth/token", issuer), "application/json", b)

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

type challenge struct {
	Verifier  string
	Challenge string
	Algorithm string
}

func generateChallenge(length int) challenge {
	c := challenge{}

	c.Verifier = generateRandomString(length)

	csum := sha256.Sum256([]byte(c.Verifier))
	c.Challenge = base64.RawURLEncoding.EncodeToString(csum[:])
	c.Algorithm = "S256"

	return c
}

func pkceFlow(issuer, clientID, audience string) (string, string) {
	challenger := generateChallenge(32)

	helper := &getAuthorizationCodeFlowHelper{}
	code := getAuthorizationCode(issuer, clientID, audience, challenger.Challenge, challenger.Algorithm, helper)

	return exchangeAuthorizationCodeForIDAndRefreshToken(issuer, clientID, challenger.Verifier, code, helper.GetCallbackURL(), &http.Client{})
}
