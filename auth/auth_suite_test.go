package auth

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
)

func TestAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../test-results/junit/auth.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Auth0KubectlAuth Auth Suite", []Reporter{junitReporter})
}
