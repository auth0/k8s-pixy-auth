package main_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAuth0ClientGoExecPlugin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth0ClientGoExecPlugin Suite")
}
