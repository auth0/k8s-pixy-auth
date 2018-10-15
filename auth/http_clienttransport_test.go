package auth_test

// import (
// 	"io/ioutil"
// 	"net/http"
// 	"net/http/httptest"
// 	"strings"

// 	. "github.com/auth0/auth0-kubectl-auth/auth"
// 	. "github.com/onsi/ginkgo"
// 	. "github.com/onsi/gomega"
// )

// type dummyRequest struct {
// 	HelloWorld string `json:"hello_world"`
// }

// var _ = Describe("HTTPClientTransport", func() {
// 	It("json encodes the request", func() {
// 		var req http.Request
// 		done := make(chan bool)

// 		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			req = *r
// 			done <- true
// 		}))
// 		defer s.Close()

// 		ct := HttpClientTransport{}
// 		go ct.Post(s.URL, &dummyRequest{HelloWorld: "no"})

// 		<-done
// 		body, _ := ioutil.ReadAll(req.Body)
// 		Expect(strings.TrimRight(string(body), "\n")).To(Equal(`{"hello_world":"no"}`))
// 	})
// })
