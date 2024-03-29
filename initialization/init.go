package initialization

import (
	"fmt"
	"path/filepath"

	"github.com/auth0/k8s-pixy-auth/auth"
	"github.com/auth0/k8s-pixy-auth/os"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

type kubeConfigInteractor interface {
	LoadConfig() (*api.Config, error)
	SaveConfig(*api.Config) error
}

type kubeConfigFileInteractor struct {
	loader *clientcmd.ClientConfigLoadingRules
}

func newDefaultKubeConfigFileInteractor() *kubeConfigFileInteractor {
	return &kubeConfigFileInteractor{
		loader: clientcmd.NewDefaultClientConfigLoadingRules(),
	}
}

func (k *kubeConfigFileInteractor) LoadConfig() (*api.Config, error) {
	config, err := k.loader.Load()
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (k *kubeConfigFileInteractor) SaveConfig(config *api.Config) error {
	return clientcmd.ModifyConfig(k.loader, *config, false)
}

// oSInteractor abstracts interacting with OS level resources
type oSInteractor interface {
	GetCurrentExecutableLocation() string
	GetHomeDirAbsolutePath() string
	DoesPathExist(path string) bool
	CreateAbsoluteFolderPath(path string) error
	CopyFile(source, destination string) error
}

// Initializer provides a way to install the k8s-pixy-auth binary as well
// as set up kube config with the auth exec information
type Initializer struct {
	kubeConfigInteractor kubeConfigInteractor
	os                   oSInteractor
}

// NewDefaultInitializer constructs an initializer with default setup
func NewDefaultInitializer() *Initializer {
	return &Initializer{
		kubeConfigInteractor: newDefaultKubeConfigFileInteractor(),
		os:                   os.DefaultInteractor{},
	}
}

// UpdateKubeConfig updates the provided context in kube config with the
// k8s-pixy-auth exec information
func (init *Initializer) UpdateKubeConfig(contextName, binaryLocation string, issuer auth.Issuer, useIDToken, withRefreshToken bool, port uint16) error {
	config, err := init.kubeConfigInteractor.LoadConfig()
	if err != nil {
		return fmt.Errorf("Error loading kube config: %s", err.Error())
	}

	if config.AuthInfos == nil {
		config.AuthInfos = map[string]*api.AuthInfo{}
	}

	authInfoName := fmt.Sprintf("%s-exec-auth", contextName)

	args := []string{"auth",
		fmt.Sprintf("--issuer-endpoint=%s", issuer.IssuerEndpoint),
		fmt.Sprintf("--client-id=%s", issuer.ClientID),
		fmt.Sprintf("--audience=%s", issuer.Audience),
		fmt.Sprintf("--port=%d", port),
	}

	if useIDToken {
		args = append(args, "--use-id-token")
	}

	if withRefreshToken {
		args = append(args, "--with-refresh-token")
	}

	config.AuthInfos[authInfoName] = &api.AuthInfo{
		Exec: &api.ExecConfig{
			Command:    binaryLocation,
			Args:       args,
			APIVersion: "client.authentication.k8s.io/v1beta1",
		},
	}

	associateClusterWithAuthInfo(config, contextName, authInfoName)

	if err = init.kubeConfigInteractor.SaveConfig(config); err != nil {
		return fmt.Errorf("Error saving kube config: %s", err.Error())
	}

	return nil
}

func associateClusterWithAuthInfo(config *api.Config, contextName, authInfoName string) {
	if config.Contexts == nil {
		config.Contexts = map[string]*api.Context{}
	}

	if config.Contexts[contextName] == nil {
		config.Contexts[contextName] = &api.Context{}
	}

	config.Contexts[contextName].AuthInfo = authInfoName
}

// InstallBinary creates the ~/.k8s-pixy-auth/bin folder if it does not
// exist and copies the currently running binary to that location. It will
// return the absolute path of the installed binary.
func (init *Initializer) InstallBinary() (string, error) {
	binaryInstallFolderPath, err := init.getBinaryInstallFolderPath()
	if err != nil {
		return "", fmt.Errorf("Error setting up the binary: %s", err.Error())
	}

	src := init.os.GetCurrentExecutableLocation()
	dest := filepath.Join(binaryInstallFolderPath, filepath.Base(src))

	err = init.os.CopyFile(src, dest)
	if err != nil {
		return "", fmt.Errorf("Error copying the binary: %s", err.Error())
	}

	return dest, nil
}

func (init *Initializer) getBinaryInstallFolderPath() (string, error) {
	absoluteHomeDirPath := init.os.GetHomeDirAbsolutePath()
	absolutePath := filepath.Join(absoluteHomeDirPath, ".k8s-pixy-auth", "bin")

	var err error
	if !init.os.DoesPathExist(absolutePath) {
		err = init.os.CreateAbsoluteFolderPath(absolutePath)
	}

	return absolutePath, err
}
