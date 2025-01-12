package awscognito

import (
	"context"
	"fmt"
	"log"
	"mognito/lib/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type ClaimsPage struct {
	IDToken string
	Claims  jwt.MapClaims
	Parts   []string
}

var (
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	loginURL     string
)

func LoginURL(cfg *config.Config) (string, error) {

	if loginURL == "" {
		loginURL = oauth2Config.AuthCodeURL(cfg.Cognito.State, oauth2.AccessTypeOnline)
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
		Scopes:       append([]string{oidc.ScopeOpenID}, cfg.Cognito.Scope...),
	}
}

func GetClaims(code string) (data *ClaimsPage, err error) {

	ctx := context.Background()

	// Exchange the authorization code for a token
	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	oidcConfig := &oidc.Config{
		ClientID: oauth2Config.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token field in oauth2 token")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID Token: %w", err)
	}

	var claims jwt.MapClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("error fetching Claims from ID Token: %w", err)
	}

	// Prepare data for rendering the template
	return &ClaimsPage{
		IDToken: rawIDToken,
		Claims:  claims,
	}, nil
}
