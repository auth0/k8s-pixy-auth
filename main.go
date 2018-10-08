package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

const hashHTML = `
<html>
	<script>
		if(window.location.hash) {
		  	window.location = "/callback?" + window.location.hash.substr(1);
		} else {
		  alert("Error! No hash!");
		}
	</script>
</html>
`

func main() {
	responseChan := make(chan url.Values)

	// we have to do this since response_mode=query only works if response_type=code
	http.HandleFunc("/hash", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(hashHTML))
	})
	http.HandleFunc("/callback", getCallbackHandler(responseChan))

	s := &http.Server{
		Addr: ":8080",
	}
	go listenAndServe(s)

	clientID := os.Args[1]
	audience := os.Args[2]

	openURL(fmt.Sprintf(
		"https://joncarl.auth0.com/authorize?client_id=%v&response_type=id_token token&redirect_uri=http://localhost:8080/hash&scope=openid email&audience=%v&state=yes&nonce=noonceyo",
		clientID,
		audience))
	tokenInfo := <-responseChan
	idToken := tokenInfo.Get("id_token")

	if err := s.Shutdown(context.Background()); err != nil {
		// Error from closing listeners, or context timeout:
		log.Printf("HTTP server Shutdown error: %v", err)
	}

	creds := v1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: "client.authentication.k8s.io/v1beta1",
		},
		Status: &v1beta1.ExecCredentialStatus{
			Token: idToken,
		},
	}

	jCreds, _ := json.Marshal(creds)
	fmt.Println(string(jCreds))

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
