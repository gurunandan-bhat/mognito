package awscognito

import (
	"context"
	"fmt"
	"log"
	"mognito/lib/config"

	"github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type ClaimsPage struct {
	RefreshToken string
	Claims       jwt.MapClaims
	Parts        []string
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

	// oidcConfig := &oidc.Config{
	// 	ClientID: oauth2Config.ClientID,
	// }
	// verifier := provider.Verifier(oidcConfig)
	// refreshToken, ok := oauth2Token.Extra("refresh_token").(string)
	// if !ok {
	// 	return nil, fmt.Errorf("no refresh_token field in oauth2 token")
	// }

	// refreshToken, err := verifier.Verify(ctx, rawRefreshToken)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to verify ID Token: %w", err)
	// }

	rawRefreshToken := oauth2Token.RefreshToken
	var claims jwt.MapClaims
	parser := jwt.NewParser()
	_, parts, err := parser.ParseUnverified(rawRefreshToken, claims)
	if err != nil {
		return nil, fmt.Errorf("error parsing (unverified) refresh Token: %w", err)
	}

	// Prepare data for rendering the template
	return &ClaimsPage{
		RefreshToken: rawRefreshToken,
		Claims:       claims,
		Parts:        parts,
	}, nil
}
