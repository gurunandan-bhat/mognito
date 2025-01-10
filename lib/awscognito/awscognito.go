package awscognito

import (
	"context"
	"errors"
	"fmt"
	"log"
	"mognito/lib/config"

	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"
)

type ClaimsPage struct {
	AccessToken string
	Claims      jwt.MapClaims
}

var (
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	loginURL     string
)

func LoginURL(cfg *config.Config) (string, error) {

	if loginURL == "" {
		loginURL = oauth2Config.AuthCodeURL("state", oauth2.AccessTypeOnline)
	}

	return loginURL, nil
}

func init() {
	var err error
	// Initialize OIDC provider
	cfg, err := config.Configuration()
	if err != nil {
		log.Fatalf("error fetching configuration: %s", err)
	}
	provider, err = oidc.NewProvider(context.Background(), cfg.Cognito.IssuerURL)
	if err != nil {
		log.Fatalf("Failed to create OIDC provider: %v", err)
	}

	// Set up OAuth2 config
	oauth2Config = oauth2.Config{
		ClientID:     cfg.Cognito.ClientID,
		ClientSecret: cfg.Cognito.ClientSecret,
		RedirectURL:  cfg.Cognito.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}
}

func GetClaims(code string) (data *ClaimsPage, err error) {

	ctx := context.Background()

	// Exchange the authorization code for a token
	rawToken, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}
	tokenString := rawToken.AccessToken

	// Parse the token (do signature verification for your use case in production)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	// Check if the token is valid and extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	// Prepare data for rendering the template
	return &ClaimsPage{
		AccessToken: tokenString,
		Claims:      claims,
	}, nil
}
