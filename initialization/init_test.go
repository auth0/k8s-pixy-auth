package initialization

import (
	"errors"
	"fmt"
	"testing"

	"github.com/auth0/k8s-pixy-auth/auth"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/tools/clientcmd/api"
)

func TestAuth0KubectlAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../test-results/junit/init.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Auth0KubectlAuth Init Suite", []Reporter{junitReporter})
}

type mockKubeConfigInteractor struct {
	LoadConfigCalled bool
	ReturnConfig     *api.Config
	SavedConfig      *api.Config
	ReturnLoadError  error
	ReturnSaveError  error
}

func (m *mockKubeConfigInteractor) LoadConfig() (*api.Config, error) {
	m.LoadConfigCalled = true
	return m.ReturnConfig, m.ReturnLoadError
}

func (m *mockKubeConfigInteractor) SaveConfig(config *api.Config) error {
	m.SavedConfig = config
	return m.ReturnSaveError
}

type mockOSInteractor struct {
	ReturnExecutableLocation            string
	ReturnGetHomeDirAbsolutePath        string
	ReturnDoesPathExist                 bool
	ReturnCreateAbsoluteFolderPathError error
	ReturnCopyFileError                 error

	DoesPathExistCalledWith            string
	CreateAbsoluteFolderPathCalledWith string
	CopyFileCalledWithSource           string
	CopyFileCalledWithDestination      string
}

func (m *mockOSInteractor) GetCurrentExecutableLocation() string {
	return m.ReturnExecutableLocation
}

func (m *mockOSInteractor) GetHomeDirAbsolutePath() string {
	return m.ReturnGetHomeDirAbsolutePath
}

func (m *mockOSInteractor) DoesPathExist(path string) bool {
	m.DoesPathExistCalledWith = path
	return m.ReturnDoesPathExist
}

func (m *mockOSInteractor) CreateAbsoluteFolderPath(path string) error {
	m.CreateAbsoluteFolderPathCalledWith = path
	return m.ReturnCreateAbsoluteFolderPathError
}

func (m *mockOSInteractor) CopyFile(source, destination string) error {
	m.CopyFileCalledWithSource = source
	m.CopyFileCalledWithDestination = destination
	return m.ReturnCopyFileError
}

var _ = Describe("init", func() {
	var kubeConfigInteractor mockKubeConfigInteractor
	var oSInteractor mockOSInteractor
	var i Initializer
	BeforeEach(func() {
		kubeConfigInteractor = mockKubeConfigInteractor{
			ReturnConfig: &api.Config{},
		}
		oSInteractor = mockOSInteractor{
			ReturnExecutableLocation: "/testing/binary",
			ReturnDoesPathExist:      true,
		}
		i = Initializer{&kubeConfigInteractor, &oSInteractor}
	})

	It("loads the current kube config", func() {
		i.UpdateKubeConfig("", "", auth.Issuer{}, false, false, 8080)

		Expect(kubeConfigInteractor.LoadConfigCalled).To(BeTrue())
	})

	It("creates the context when the context does not exist", func() {
		i.UpdateKubeConfig("context-name", "", auth.Issuer{}, false, false, 8080)

		Expect(kubeConfigInteractor.SavedConfig.Contexts["context-name"].AuthInfo).To(Equal("context-name-exec-auth"))
		Expect(kubeConfigInteractor.SavedConfig.Contexts["context-name"].Cluster).To(BeEmpty())
	})

	It("changes the context user to the exec user", func() {
		kubeConfigInteractor.ReturnConfig = &api.Config{
			Contexts: map[string]*api.Context{
				"context-name": {
					AuthInfo: "context-name",
					Cluster:  "cluster",
				},
			},
		}
		i.UpdateKubeConfig("context-name", "", auth.Issuer{}, false, false, 8080)

		Expect(kubeConfigInteractor.SavedConfig.Contexts["context-name"].AuthInfo).To(Equal("context-name-exec-auth"))
		Expect(kubeConfigInteractor.SavedConfig.Contexts["context-name"].Cluster).To(Equal("cluster"))
	})

	It("adds the issuer information as arguments", func() {
		issuer := auth.Issuer{IssuerEndpoint: "issuer", ClientID: "client-id", Audience: "audience"}
		i.UpdateKubeConfig("context-name", "", issuer, false, false, 8080)

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name-exec-auth"].Exec.Args).To(Equal([]string{
			"auth",
			fmt.Sprintf("--issuer-endpoint=%s", issuer.IssuerEndpoint),
			fmt.Sprintf("--client-id=%s", issuer.ClientID),
			fmt.Sprintf("--audience=%s", issuer.Audience),
			fmt.Sprintf("--port=%d", 8080)}))
	})

	It("adds the use id token argument when using the id token", func() {
		i.UpdateKubeConfig("context-name", "", auth.Issuer{}, true, false, 8080)

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name-exec-auth"].Exec.Args).To(Equal([]string{
			"auth",
			"--issuer-endpoint=",
			"--client-id=",
			"--audience=",
			"--port=8080",
			"--use-id-token"}))
	})

	It("adds the with refresh token argument when wanting to use the refresh token", func() {
		i.UpdateKubeConfig("context-name", "", auth.Issuer{}, false, true, 8080)

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name-exec-auth"].Exec.Args).To(Equal([]string{
			"auth",
			"--issuer-endpoint=",
			"--client-id=",
			"--audience=",
			"--port=8080",
			"--with-refresh-token"}))
	})

	It("adds a non-default callback port to the kubeconfig", func() {
		i.UpdateKubeConfig("context-name", "", auth.Issuer{}, false, false, 1337)

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name-exec-auth"].Exec.Args).To(Equal([]string{
			"auth",
			"--issuer-endpoint=",
			"--client-id=",
			"--audience=",
			"--port=1337"}))
	})

	It("adds the binary location", func() {
		i.UpdateKubeConfig("context-name", "binary-location", auth.Issuer{}, false, false, 8080)

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name-exec-auth"].Exec.Command).To(Equal("binary-location"))
	})

	It("adds the correct API version", func() {
		i.UpdateKubeConfig("context-name", "", auth.Issuer{}, false, false, 8080)

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name-exec-auth"].Exec.APIVersion).To(Equal("client.authentication.k8s.io/v1beta1"))
	})

	It("keeps existing auth info", func() {
		contextAuth := &api.AuthInfo{
			ClientCertificate: "i am cert",
			ClientKey:         "i am key",
		}
		kubeConfigInteractor.ReturnConfig = &api.Config{
			AuthInfos: map[string]*api.AuthInfo{
				"context-name": contextAuth,
			},
		}

		i.UpdateKubeConfig("context-name", "", auth.Issuer{}, false, false, 8080)

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name"]).To(Equal(contextAuth))
	})

	It("returns any errors from loading a config", func() {
		kubeConfigInteractor.ReturnLoadError = errors.New("someerror")
		err := i.UpdateKubeConfig("", "", auth.Issuer{}, false, false, 8080)

		Expect(err.Error()).To(Equal("Error loading kube config: someerror"))
	})

	It("returns any errors from saving a config", func() {
		kubeConfigInteractor.ReturnSaveError = errors.New("someerror")
		err := i.UpdateKubeConfig("", "", auth.Issuer{}, false, false, 8080)

		Expect(err.Error()).To(Equal("Error saving kube config: someerror"))
	})

	It("creates the ~/.k8s-pixy-auth/bin folder if it doesn't exist", func() {
		oSInteractor.ReturnGetHomeDirAbsolutePath = "/Users/testing/"
		oSInteractor.ReturnDoesPathExist = false
		expectedBinPath := "/Users/testing/.k8s-pixy-auth/bin"
		i.InstallBinary()

		Expect(oSInteractor.DoesPathExistCalledWith).To(Equal(expectedBinPath))
		Expect(oSInteractor.CreateAbsoluteFolderPathCalledWith).To(Equal(expectedBinPath))
	})

	It("returns an error if creating the folder is not successful", func() {
		oSInteractor.ReturnDoesPathExist = false
		oSInteractor.ReturnCreateAbsoluteFolderPathError = errors.New("folder creation error")
		_, err := i.InstallBinary()

		Expect(err.Error()).To(Equal("Error setting up the binary: folder creation error"))
	})

	It("copies the binary to the ~/.k8s-pixy-auth/bin folder", func() {
		oSInteractor.ReturnExecutableLocation = "/tmp/binary"
		oSInteractor.ReturnGetHomeDirAbsolutePath = "/Users/testing/"
		i.InstallBinary()

		Expect(oSInteractor.CopyFileCalledWithSource).To(Equal("/tmp/binary"))
		Expect(oSInteractor.CopyFileCalledWithDestination).To(Equal("/Users/testing/.k8s-pixy-auth/bin/binary"))
	})

	It("returns an error when copying is unsuccessful", func() {
		oSInteractor.ReturnCopyFileError = errors.New("copy file error")

		_, err := i.InstallBinary()

		Expect(err.Error()).To(Equal("Error copying the binary: copy file error"))
	})

})
