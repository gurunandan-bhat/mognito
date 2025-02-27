package service

import (
	"fmt"
	"mognito/lib/awscognito"
	"net/http"
)

func (s *Service) HandleCallback(w http.ResponseWriter, r *http.Request) error {

	code := r.URL.Query().Get("code")
	fmt.Println("Code: ", code)
	claims, err := awscognito.GetClaims(code)
	if err != nil {
		return err
	}

	if err := s.Template.Render(w, "claims", claims); err != nil {
		return err
	}

	return nil
}
