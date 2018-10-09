package main

import (
	"encoding/json"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

func main() {
	domain := os.Args[1]
	clientID := os.Args[2]
	audience := os.Args[3]

	idToken := getAuthInfo(domain, clientID, audience)

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
