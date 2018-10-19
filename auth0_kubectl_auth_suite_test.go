package main

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAuth0KubectlAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth0KubectlAuth Suite")
}
