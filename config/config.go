package config

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	yaml "gopkg.in/yaml.v2"
)

// Configuration ...
type Configuration struct {
	Clients    map[string]ClientConfiguration `yaml:"clients"`
	configFile io.ReadWriter                  `yaml:"-"`
}

// ClientConfiguration ...
type ClientConfiguration struct {
	IDToken      string `yaml:"idToken"`
	RefreshToken string `yaml:"refreshToken"`
}

// NewConfig creates and returns a config object that reads from the default
// config file
func NewConfig(r io.ReadWriter) *Configuration {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		panic(fmt.Errorf("fatal error reading config reader: %s", err))
	}
	c := Configuration{
		Clients:    make(map[string]ClientConfiguration),
		configFile: r,
	}
	err = yaml.Unmarshal(b, &c)
	if err != nil {
		panic(fmt.Errorf("Unmarshal: %v", err))
	}

	return &c
}

func getHomeDir() string {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}
	return usr.HomeDir
}

// NewConfigFromFile builds a new Configuration object using the default config file
func NewConfigFromFile() *Configuration {
	configFileName := "config"
	configFilePath := filepath.Join(getHomeDir(), ".auth0-kubectl-auth")

	fileLoc := filepath.Join(configFilePath, configFileName)

	var r io.ReadWriter
	var err error

	if !pathExists(fileLoc) {
		err := os.MkdirAll(configFilePath, os.ModePerm)
		if err != nil {
			panic(fmt.Errorf("fatal error creating directory: %s", err))
		}

		r, err = os.OpenFile(fileLoc, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
		if err != nil {
			panic(fmt.Errorf("fatal error creating file: %s", err))
		}
	} else {
		r, err = os.OpenFile(fileLoc, os.O_RDWR, 0600)
		if err != nil {
			panic(fmt.Errorf("fatal error reading config file: %s", err))
		}
	}

	return NewConfig(r)
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// GetTokens ...
func (c *Configuration) GetTokens(clientID string) (string, string) {
	client, ok := c.Clients[clientID]
	if !ok {
		return "", ""
	}

	return client.IDToken, client.RefreshToken
}

// SaveTokens ...
func (c *Configuration) SaveTokens(clientID, idToken, refreshToken string) {

	c.Clients[clientID] = ClientConfiguration{
		IDToken:      idToken,
		RefreshToken: refreshToken,
	}

	b, err := yaml.Marshal(&c)
	if err != nil {
		panic(fmt.Errorf("Marshal: %v", err))
	}

	if file, ok := c.configFile.(*os.File); ok {
		file.Truncate(0)
		file.Seek(0, 0)
	}

	_, err = c.configFile.Write(b)
	if err != nil {
		panic(fmt.Errorf("Error caching tokens: %v", err))
	}
}
