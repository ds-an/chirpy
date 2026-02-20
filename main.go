// Package chirpy is a project showcasing a Go HTTP server for Boot.dev
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

var profane = map[string]struct{}{
	"kerfuffle": {},
	"sharbert":  {},
	"fornax":    {},
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

// "any" and "interface{}" are identical. "any" is more modern and idiomatic
func respondWithJSON(w http.ResponseWriter, code int, payload any) {
	respBody := payload
	data, err := json.Marshal(respBody)
	if err != nil {
		log.Printf("Error marshaling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err = w.Write(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorResponse struct {
		Error string `json:"error"`
	}
	payload := errorResponse{
		Error: msg,
	}
	respondWithJSON(w, code, payload)
}

func replaceProfane(s string) string {
	splitString := strings.Split(s, " ")
	for i ,word := range splitString {
		if _, ok := profane[strings.ToLower(word)]; ok {
			splitString[i] = "****"
		}
	}
	return strings.Join(splitString, " ")
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

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}
	type CleanText struct {
		CleanedBody string `json:"cleaned_body"`
	}
	payload := CleanText{
		CleanedBody: replaceProfane(params.Body),
	}
	respondWithJSON(w, http.StatusOK, payload)
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
