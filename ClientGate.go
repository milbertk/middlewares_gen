package middlewares_gen

import (
	"net/http"
	"net/url"
	"strings"
)

type ClientGateConfig struct {
	// Exact allowed origins (full scheme+host, e.g. "https://app.example.com")
	AllowedOrigins []string
	// Optional: allow by host suffix (".example.org" = any subdomain of example.org)
	AllowedOriginSuffixes []string

	AllowedMethods   []string // defaults applied if empty
	AllowedHeaders   []string // defaults applied if empty
	AllowCredentials bool     // true if you use cookies/Authorization
	AllowNativeApps  bool     // allow requests with NO Origin (Android/iOS, curl)
}

func ClientGate(cfg ClientGateConfig) func(http.Handler) http.Handler {
	allowedMethods := joinOrDefault(cfg.AllowedMethods, []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
	allowedHeaders := joinOrDefault(cfg.AllowedHeaders, []string{"Authorization", "Content-Type"})

	isAllowedOrigin := func(origin string) bool {
		if origin == "" {
			return false
		}
		// Exact match
		for _, o := range cfg.AllowedOrigins {
			if origin == o {
				return true
			}
		}
		// Suffix/host match
		if len(cfg.AllowedOriginSuffixes) > 0 {
			u, err := url.Parse(origin)
			if err == nil && u.Hostname() != "" {
				host := strings.ToLower(u.Hostname())
				for _, s := range cfg.AllowedOriginSuffixes {
					s = strings.ToLower(strings.TrimSpace(s))
					if s == "" {
						continue
					}
					if strings.HasPrefix(s, ".") {
						root := strings.TrimPrefix(s, ".")
						if strings.HasSuffix(host, "."+root) {
							return true // e.g., foo.example.org
						}
					} else if host == s {
						return true // exact host match
					}
				}
			}
		}
		return false
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Help caches/proxies vary correctly
			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")

			if origin != "" {
				// Browser path: enforce allow-list
				if !isAllowedOrigin(origin) {
					// Block preflights explicitly
					if r.Method == http.MethodOptions {
						http.Error(w, "forbidden origin", http.StatusForbidden)
						return
					}
					// For non-OPTIONS, omit CORS headers (browser JS will be blocked)
					next.ServeHTTP(w, r)
					return
				}

				// Allowed browser origin → set CORS headers
				w.Header().Set("Access-Control-Allow-Origin", origin)
				if cfg.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
				w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)

				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}

				next.ServeHTTP(w, r)
				return
			}

			// No Origin header (native apps / curl / servers)
			if cfg.AllowNativeApps {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, "origin required", http.StatusForbidden)
		})
	}
}

func joinOrDefault(v, def []string) string {
	if len(v) == 0 {
		return strings.Join(def, ", ")
	}
	return strings.Join(v, ", ")
}

/*
package routers

import (
	"github.com/gorilla/mux"
	"github.com/milbertk/usersAppAK/handlers"
	husercreate "github.com/milbertk/usersAppAK/handlers/HuserCreate"
	huserlogin "github.com/milbertk/usersAppAK/handlers/HuserLogin"

	"github.com/milbertk/usersAppAK/middlewares"
)

func NewRouter() *mux.Router {
	router := mux.NewRouter()

	// Apply domain filter (browsers) and allow native apps (no Origin)
	router.Use(middlewares.ClientGate(middlewares.ClientGateConfig{
		AllowedOrigins:        []string{"https://app.example.com", "https://admin.example.com"},
		AllowedOriginSuffixes: []string{".example.org"}, // optional
		AllowCredentials:      true,
		AllowNativeApps:       true, // Android/iOS (and other non-browser clients) are allowed; JWT will protect.
		AllowedHeaders:        []string{"Authorization", "Content-Type"},
	}))

	// Routes (your JWT middleware stays as you already have it)
	router.HandleFunc("/", handlers.TestHandler).Methods("GET")
	router.HandleFunc("/createuser", husercreate.HuserCreate).Methods("GET")
	router.HandleFunc("/login", huserlogin.HuserLogin).Methods("POST")

	return router
}
*/

/*
# Disallowed browser origin
curl -i -H 'Origin: https://evil.com' http://localhost:8080/

# Allowed browser origin (preflight)
curl -i -X OPTIONS \
  -H 'Origin: https://app.example.com' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: Authorization, Content-Type' \
  http://localhost:8080/login

# Native (no Origin) → allowed (JWT still required on protected routes)
curl -i http://localhost:8080/

*/
