package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/spf13/viper"
)

const (
	defaultConfigFileName = ".mognito.json"
)

type Config struct {
	InProduction bool   `json:"inProduction,omitempty"`
	AppRoot      string `json:"appRoot,omitempty"`
	Db           struct {
		User                 string `json:"user,omitempty"`
		Passwd               string `json:"passwd,omitempty"`
		Net                  string `json:"net,omitempty"`
		Addr                 string `json:"addr,omitempty"`
		DBName               string `json:"dbName,omitempty"`
		ParseTime            bool   `json:"parseTime,omitempty"`
		Loc                  string `json:"loc,omitempty"`
		AllowNativePasswords bool   `json:"allowNativePasswords,omitempty"`
	} `json:"db,omitempty"`
	Cognito struct {
		ClientID     string   `json:"clientID,omitempty"`
		ClientSecret string   `json:"clientSecret,omitempty"`
		RedirectURL  string   `json:"redirectURL,omitempty"`
		IssuerURL    string   `json:"issuerURL,omitempty"`
		Scope        []string `json:"scope,omitempty"`
		State        string   `json:"-"`
	} `json:"cognito,omitempty"`
	Security struct {
		CSRFKey string `json:"csrfKey,omitempty"`
	} `json:"security,omitempty"`
	Session struct {
		Name        string `json:"name,omitempty"`
		Path        string `json:"path,omitempty"`
		Domain      string `json:"domain,omitempty"`
		MaxAgeHours int    `json:"maxAgeHours,omitempty"`
	} `json:"session,omitempty"`
}

var c *Config
var once sync.Once

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func Configuration(configFileName ...string) (*Config, error) {

	var errOut error
	once.Do(func() {

		var cfName string
		switch len(configFileName) {
		case 0:
			dirname, err := os.UserHomeDir()
			if err != nil {
				errOut = err
			}
			cfName = filepath.Join(dirname, defaultConfigFileName)
		case 1:
			cfName = configFileName[0]
		default:
			errOut = errors.New("incorrect arguments for configuration file name")
			return
		}

		viper.SetConfigFile(cfName)
		if err := viper.ReadInConfig(); err != nil {
			errOut = err
			return
		}

		if err := viper.Unmarshal(&c); err != nil {
			errOut = err
			return
		}

		state, err := randString(16)
		if err != nil {
			errOut = fmt.Errorf("error generating random string: %w", err)
			return
		}
		c.Cognito.State = state
	})

	state, err := randString(16)
	if err != nil {
		errOut = fmt.Errorf("error generating random string: %w", err)
		return nil, errOut
	}
	c.Cognito.State = state

	return c, errOut
}
