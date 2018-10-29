package initialization

import (
	"errors"
	"fmt"
	"testing"

	"github.com/auth0/auth0-kubectl-auth/auth"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/tools/clientcmd/api"
)

func TestAuth0KubectlAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth0KubectlAuth Init Suite")
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
		i.UpdateKubeConfig("", "", auth.Issuer{})

		Expect(kubeConfigInteractor.LoadConfigCalled).To(BeTrue())
	})

	It("creates the context when the context does not exist", func() {
		i.UpdateKubeConfig("context-name", "", auth.Issuer{})

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
		i.UpdateKubeConfig("context-name", "", auth.Issuer{})

		Expect(kubeConfigInteractor.SavedConfig.Contexts["context-name"].AuthInfo).To(Equal("context-name-exec-auth"))
		Expect(kubeConfigInteractor.SavedConfig.Contexts["context-name"].Cluster).To(Equal("cluster"))
	})

	It("adds the issuer information as arguments", func() {
		issuer := auth.Issuer{IssuerEndpoint: "issuer", ClientID: "client-id", Audience: "audience"}
		i.UpdateKubeConfig("context-name", "", issuer)

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name-exec-auth"].Exec.Args).To(Equal([]string{
			"auth",
			fmt.Sprintf("--issuer-endpoint=%s", issuer.IssuerEndpoint),
			fmt.Sprintf("--client-id=%s", issuer.ClientID),
			fmt.Sprintf("--audience=%s", issuer.Audience)}))
	})

	It("adds the binary location", func() {
		i.UpdateKubeConfig("context-name", "binary-location", auth.Issuer{})

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name-exec-auth"].Exec.Command).To(Equal("binary-location"))
	})

	It("adds the correct API version", func() {
		i.UpdateKubeConfig("context-name", "", auth.Issuer{})

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

		i.UpdateKubeConfig("context-name", "", auth.Issuer{})

		Expect(kubeConfigInteractor.SavedConfig.AuthInfos["context-name"]).To(Equal(contextAuth))
	})

	It("returns any errors from loading a config", func() {
		kubeConfigInteractor.ReturnLoadError = errors.New("someerror")
		err := i.UpdateKubeConfig("", "", auth.Issuer{})

		Expect(err.Error()).To(Equal("Error loading kube config: someerror"))
	})

	It("returns any errors from saving a config", func() {
		kubeConfigInteractor.ReturnSaveError = errors.New("someerror")
		err := i.UpdateKubeConfig("", "", auth.Issuer{})

		Expect(err.Error()).To(Equal("Error saving kube config: someerror"))
	})

	It("creates the ~/.auth0-kubectl-auth/bin folder if it doesn't exist", func() {
		oSInteractor.ReturnGetHomeDirAbsolutePath = "/Users/testing/"
		oSInteractor.ReturnDoesPathExist = false
		expectedBinPath := "/Users/testing/.auth0-kubectl-auth/bin"
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

	It("copies the binary to the ~/.auth0-kubectl-auth/bin folder", func() {
		oSInteractor.ReturnExecutableLocation = "/tmp/binary"
		oSInteractor.ReturnGetHomeDirAbsolutePath = "/Users/testing/"
		i.InstallBinary()

		Expect(oSInteractor.CopyFileCalledWithSource).To(Equal("/tmp/binary"))
		Expect(oSInteractor.CopyFileCalledWithDestination).To(Equal("/Users/testing/.auth0-kubectl-auth/bin/binary"))
	})

	It("returns an error when copying is unsuccessful", func() {
		oSInteractor.ReturnCopyFileError = errors.New("copy file error")

		_, err := i.InstallBinary()

		Expect(err.Error()).To(Equal("Error copying the binary: copy file error"))
	})

})
