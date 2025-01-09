package service

import (
	"fmt"
	"mognito/lib/awscognito"
	"net/http"
)

type IndexPageData struct {
	Message  string
	LoginURL string
}

func (s *Service) Index(w http.ResponseWriter, r *http.Request) error {

	url, err := awscognito.LoginURL(s.Config)
	if err != nil {
		return fmt.Errorf("error fetching login url: %w", err)
	}

	data := IndexPageData{
		Message:  "Hello, World!",
		LoginURL: url,
	}

	if err := s.Template.Render(w, "index", data); err != nil {
		return err
	}

	return nil
}
