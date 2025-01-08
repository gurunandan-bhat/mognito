package service

import (
	"net/http"
)

type IndexPageData struct {
	Message string
}

func (s *Service) Index(w http.ResponseWriter, r *http.Request) error {

	data := IndexPageData{
		Message: "Hello, World!",
	}

	if err := s.Template.Render(w, "index", data); err != nil {
		return err
	}

	return nil
}
