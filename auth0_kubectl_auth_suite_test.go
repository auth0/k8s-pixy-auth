package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestAuth0KubectlAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth0KubectlAuth Suite")
}
