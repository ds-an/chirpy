// Package chirpy is a project showcasing a Go HTTP server for Boot.dev
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fsHitsHTML := 
`<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
</html>`
	fsHitsMessage := fmt.Sprintf(fsHitsHTML, cfg.fileserverHits.Load())
	_, err := w.Write([]byte(fsHitsMessage))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func (cfg *apiConfig) metricsResetHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Store(0)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("OK"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	if len(params.Body) <= 140 {
		type valid struct {
			Valid bool `json:"valid"`
		}

		respBody := valid{
			Valid: true,
		}
		data, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshaling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	} else {
		type error struct {
			Error string `json:"error"`
		}
		respBody := error{
			Error: "Chirp is too long",
		}
		data, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshaling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_, err = w.Write(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
}

func main() {
	mux := http.NewServeMux()
	appHandler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	apiCfg := apiConfig{
		fileserverHits: atomic.Int32{},
	}
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(appHandler))
	hzh := http.HandlerFunc(healthzHandler)
	mux.Handle("GET /api/healthz", hzh)
	mh := http.HandlerFunc(apiCfg.metricsHandler)
	mux.Handle("GET /admin/metrics", mh)
	mrh := http.HandlerFunc(apiCfg.metricsResetHandler)
	mux.Handle("POST /admin/reset", mrh)

	vch := http.HandlerFunc(validateChirpHandler)
	mux.Handle("POST /api/validate_chirp", vch)

	server := http.Server{
		Addr: ":8080",
		Handler: mux,
	}

	err := server.ListenAndServe()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
