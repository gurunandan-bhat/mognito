package config

import (
	"errors"
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
		ClientID      string   `json:"clientID,omitempty"`
		ClientSecret  string   `json:"clientSecret,omitempty"`
		LoginEndpoint string   `json:"loginEndpoint,omitempty"`
		RedirectURL   string   `json:"redirectURL,omitempty"`
		IssuerURL     string   `json:"issuerURL,omitempty"`
		Scope         []string `json:"scope,omitempty"`
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
		}

		viper.SetConfigFile(cfName)
		if err := viper.ReadInConfig(); err != nil {
			errOut = err
		}

		if err := viper.Unmarshal(&c); err != nil {
			errOut = err
		}
	})

	return c, errOut
}
