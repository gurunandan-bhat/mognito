package service

import (
	"log"
	"mognito/lib/config"
	"mognito/lib/cstore"
	"mognito/lib/model"
	"mognito/lib/render"
	"net/http"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/gorilla/csrf"
)

type Service struct {
	Muxer        *chi.Mux
	Config       *config.Config
	Model        *model.Model
	SessionStore *cstore.SessionStore
	Template     *render.Templates
}

func NewService(cfg *config.Config) (*Service, error) {

	mux := chi.NewRouter()

	// force a redirect to https:// in production
	if cfg.InProduction {
		mux.Use(middleware.SetHeader(
			"Strict-Transport-Security",
			"max-age=63072000; includeSubDomains",
		))
	}

	mux.Use(middleware.RequestID)
	mux.Use(middleware.RealIP)
	mux.Use(middleware.Logger)
	mux.Use(middleware.Recoverer)

	mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	csrfMiddleware := csrf.Protect(
		[]byte(cfg.Security.CSRFKey),
		csrf.Secure(cfg.InProduction),
		csrf.SameSite(csrf.SameSiteStrictMode),
	)
	mux.Use(csrfMiddleware)

	store := cstore.NewStore(cfg)

	model, err := model.NewModel(cfg)
	if err != nil {
		log.Fatalf("Error initializing database connection: %s", err)
	}

	// Static file handler
	filesDir := http.Dir(filepath.Join(cfg.AppRoot, "assets"))
	fs := http.FileServer(filesDir)
	mux.Handle("/assets/*", http.StripPrefix("/assets", fs))

	template, err := render.NewTemplates(filepath.Join(cfg.AppRoot, "templates"))
	if err != nil {
		log.Fatalf("Cannot build template cache: %s", err)
	}

	s := &Service{
		SessionStore: store,
		Config:       cfg,
		Model:        model,
		Muxer:        mux,
		Template:     template,
	}

	s.setRoutes()

	return s, nil
}

func (s *Service) setRoutes() {

	s.Muxer.Method(http.MethodGet, "/", ServiceHandler(s.Index))
	s.Muxer.Method(http.MethodGet, "/mognito", ServiceHandler(s.HandleCallback))
}
