package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/juliushill42/RepoJail/internal/jail"
	"github.com/juliushill42/RepoJail/internal/webui"
)

type Server struct {
	manager *jail.Manager
	token   string
	logger  *log.Logger
	started time.Time
}

func New(manager *jail.Manager, token string, logger *log.Logger) *Server {
	return &Server{manager: manager, token: token, logger: logger, started: time.Now()}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/api/v1/status", s.auth(s.status))
	mux.HandleFunc("/api/v1/jails", s.auth(s.jails))
	mux.HandleFunc("/api/v1/jails/", s.auth(s.jailRoute))
	mux.Handle("/", webui.Handler())
	return securityHeaders(requestLog(s.logger, mux))
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "repojail", "watermark": `":"`})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"root":           s.manager.Root(),
		"isolation":      s.manager.IsolationMode(),
		"active_jails":   len(s.manager.List()),
		"uptime_seconds": int(time.Since(s.started).Seconds()),
	})
}

func (s *Server) jails(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"jails": s.manager.List()})
	case http.MethodPost:
		var req jail.CreateRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		j, err := s.manager.Create(r.Context(), req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, j)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) jailRoute(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/jails/")
	parts := strings.Split(strings.Trim(tail, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			j, ok := s.manager.Get(id)
			if !ok {
				writeError(w, http.StatusNotFound, os.ErrNotExist)
				return
			}
			writeJSON(w, http.StatusOK, j)
		case http.MethodDelete:
			if err := s.manager.Destroy(id, "api-delete"); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					writeError(w, http.StatusNotFound, err)
				} else {
					writeError(w, http.StatusBadRequest, err)
				}
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w)
		}
		return
	}
	switch parts[1] {
	case "exec":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var req jail.ExecRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		result, err := s.manager.Exec(r.Context(), id, req)
		if err != nil {
			code := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				code = http.StatusNotFound
			}
			writeError(w, code, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "events":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		events, err := s.manager.Events(id, limit)
		if err != nil {
			code := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				code = http.StatusNotFound
			}
			writeError(w, code, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": events})
	default:
		writeError(w, http.StatusNotFound, errors.New("not found"))
	}
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	if s.token == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(got) != len(s.token) || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		next(w, r)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]any{"ok": false, "error": err.Error()})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func requestLog(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Printf("method=%s path=%s duration=%s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

func Run(ctx context.Context, addr string, handler http.Handler, logger *log.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      20 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Printf("listening on http://%s", addr)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
