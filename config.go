package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	yaml "gopkg.in/yaml.v2"
)

const configFileName = "config"
const configFilePath = "$HOME/.auth0-k8s-client-go-exec-plugin"

// Configuration ...
type Configuration struct {
	Clients map[string]ClientConfiguration `yaml:"clients"`
}

// ClientConfiguration ...
type ClientConfiguration struct {
	IDToken      string `yaml:"idToken"`
	RefreshToken string `yaml:"refreshToken"`
}

// NewConfig creates and returns a config object that reads from the default
// config file
func NewConfig(r io.ReadWriter) Configuration {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		panic(fmt.Errorf("fatal error reading config reader: %s", err))
	}

	c := Configuration{}
	err = yaml.Unmarshal(b, &c)
	if err != nil {
		panic(fmt.Errorf("Unmarshal: %v", err))
	}

	return c
}

func newConfigFromFile() Configuration {
	if len(configFileName) > 0 && len(configFilePath) > 0 {
		fileLoc := filepath.Join(configFilePath, configFileName)
		if !pathExists(fileLoc) {
			return Configuration{}
		}

		r, err := os.Open(fileLoc)
		if err != nil {
			panic(fmt.Errorf("fatal error config file: %s", err))
		}
		return NewConfig(r)
	}

	return Configuration{}
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

// save saves the configuration file using the name and path on the
// configuration object. If no name and path are set it silently continues
func (c *Configuration) save() {
	if len(configFileName) == 0 && len(configFilePath) == 0 {
		return
	}

	if !pathExists(configFilePath) {
		os.MkdirAll(configFilePath, os.ModeDir)
	}

	fileLoc := filepath.Join(configFilePath, configFileName)

	m, err := yaml.Marshal(c)
	if err != nil {
		panic(fmt.Errorf("fatal error marshaling config file: %s", err))
	}

	err = ioutil.WriteFile(fileLoc, []byte(m), 0644)
	if err != nil {
		panic(fmt.Errorf("fatal error saving config file: %s", err))
	}
}
