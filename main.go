// Package chirpy is a project showcasing a Go HTTP server for Boot.dev
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ds-an/chirpy/internal/auth"
	"github.com/ds-an/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries *database.Queries
	platformType string
	jwtSecret string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token			string		`json:"token"`
	RefreshToken string	`json:"refresh_token"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type loginParams struct {
	Email string `json:"email"`
	Password string `json:"password"`
	// ExpiresInSeconds *int `json:"expires_in_seconds"`
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

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platformType != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}
	w.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Store(0)

	err := cfg.dbQueries.ResetUsers(r.Context())
	if err != nil {
		log.Printf("Error resetting users: %s", err)
		w.WriteHeader(500)
		return
	}
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

// func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
// 	type chirp struct {
// 		Body string `json:"body"`
// 	}
// 	decoder := json.NewDecoder(r.Body)
// 	params := chirp{}
// 	err := decoder.Decode(&params)
// 	if err != nil {
// 		log.Printf("Error decoding chirp: %s", err)
// 		w.WriteHeader(500)
// 		return
// 	}
//
// 	if len(params.Body) > 140 {
// 		respondWithError(w, 400, "Chirp is too long")
// 		return
// 	}
// 	type CleanText struct {
// 		CleanedBody string `json:"cleaned_body"`
// 	}
// 	payload := CleanText{
// 		CleanedBody: replaceProfane(params.Body),
// 	}
// 	respondWithJSON(w, http.StatusOK, payload)
// }

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	type incomingChirp struct {
		Body string `json:"body"`
		// UserID uuid.UUID `json:"user_id"`
	}
	decoder := json.NewDecoder(r.Body)
	params := incomingChirp{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding chirp: %s", err)
		w.WriteHeader(500)
		return
	}

	authToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	userID, err := auth.ValidateJWT(authToken, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	chirpParams := database.CreateChirpParams{
		Body: params.Body,
		UserID: userID,
	}

	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), chirpParams)
	if err != nil {
		log.Printf("Error adding chirp to db: %s", err)
		w.WriteHeader(500)
		return
	}

	payload := Chirp{
		ID: chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body: replaceProfane(chirp.Body),
		UserID: chirp.UserID,
	}

	// type CleanText struct {
	// 	CleanedBody string `json:"cleaned_body"`
	// }
	// payload := CleanText{
	// 	CleanedBody: replaceProfane(params.Body),
	// }
	respondWithJSON(w, http.StatusCreated, payload)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.dbQueries.GetChirps(r.Context())
	if err != nil {
		log.Printf("Error adding chirp to db: %s", err)
		w.WriteHeader(500)
		return
	}
	chirpsPayload := []Chirp{}
	for _, chirp := range chirps {
		chirpsPayload = append(chirpsPayload, Chirp{
			ID: chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body: replaceProfane(chirp.Body),
			UserID: chirp.UserID,
		})
	}
	respondWithJSON(w, http.StatusOK, chirpsPayload)
}

func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error parsing chirp ID: %s", err)
		w.WriteHeader(500)
		return
	}
	chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		log.Printf("Error getting chirp from db: %s", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	chirpPayload := Chirp{
		ID: chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body: replaceProfane(chirp.Body),
		UserID: chirp.UserID,
	}
	respondWithJSON(w, http.StatusOK, chirpPayload)
}

func (cfg *apiConfig) deleteChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error parsing chirp ID: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		log.Printf("Error getting chirp from db: %s", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if userID != chirp.UserID {
		chirpErr := fmt.Sprintf("Chirp doesn't belong to user %s", userID) 
		respondWithError(w, http.StatusForbidden, chirpErr) 
		return
	}

	err = cfg.dbQueries.DeleteChirp(r.Context(), chirp.ID)
	if err != nil {
		log.Printf("Error deleting chirp from db: %s", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := loginParams{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding email: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if params.Email == "" || params.Password == "" {
		log.Printf("Error, empty field: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	userParams := database.CreateUserParams{
		Email: params.Email,
		HashedPassword: hashedPassword,
	}
	user, err := cfg.dbQueries.CreateUser(r.Context(), userParams)
	if err != nil {
		log.Printf("Error creating user: %s", err)
		w.WriteHeader(500)
		return
	}
	newUser := User{
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
	}
	respondWithJSON(w, http.StatusCreated, newUser)
}

func (cfg *apiConfig) userLoginHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := loginParams{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding email: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if params.Email == "" || params.Password == "" {
		log.Printf("Error, empty field: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// defaultExpirationTime := 60 * 60
	// if params.ExpiresInSeconds == nil || *params.ExpiresInSeconds > defaultExpirationTime{
	// 	params.ExpiresInSeconds = &defaultExpirationTime 
	// }

	const loginErr = "Incorrect email or password"
	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, loginErr)
		return
	}
	match, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized,  loginErr)
		return
	}
	if !match {
		respondWithError(w, http.StatusUnauthorized,   loginErr)
		return
	}

	jwtToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Duration(3600) * time.Second)
	if err != nil {
		jwtErr := fmt.Sprintf("Failed to create JWT token for user with id %s", user.ID) 
		respondWithError(w, http.StatusInternalServerError, jwtErr)
		return
	}

	refreshTokenParams := database.CreateRefreshTokenParams{
		Token: auth.MakeRefreshToken(),
		UserID: user.ID,
		ExpiresAt: time.Now().UTC().Add(60 * 24 * time.Hour),
	}

	refreshToken, err := cfg.dbQueries.CreateRefreshToken(r.Context(), refreshTokenParams)
	if err != nil {
		refreshTokenErr := fmt.Sprintf("Failed to create refresh token for user with id %s", user.ID) 
		respondWithError(w, http.StatusInternalServerError, refreshTokenErr)
		return
	}

	userPayload := User{
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
		Token: jwtToken,
		RefreshToken: refreshToken.Token,
	}
	respondWithJSON(w, http.StatusOK, userPayload)
}

func (cfg *apiConfig) userUpdateHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	decoder := json.NewDecoder(r.Body)
	newLoginParams := loginParams{}
	err = decoder.Decode(&newLoginParams)
	if err != nil {
		log.Printf("Error decoding new login parameters: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	hashedPassword, err := auth.HashPassword(newLoginParams.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	userParams := database.UpdateUserParams{
		Email: newLoginParams.Email,
		HashedPassword: hashedPassword,
		ID: userID,
	}
	userUpdated, err := cfg.dbQueries.UpdateUser(r.Context(), userParams)
	if err != nil {
		log.Printf("Error creating user: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	newUser := User{
		ID: userUpdated.ID,
		CreatedAt: userUpdated.CreatedAt,
		UpdatedAt: userUpdated.UpdatedAt,
		Email: userUpdated.Email,
	}
	respondWithJSON(w, http.StatusOK, newUser)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	refreshToken, err := cfg.dbQueries.GetRefreshToken(r.Context(), tokenString)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if refreshToken.RevokedAt.Valid || refreshToken.ExpiresAt.Before(time.Now().UTC()) {
		respondWithError(w, http.StatusUnauthorized, "Refresh token expired or revoked")
		return
	}

	user, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), refreshToken.Token)
	if err != nil {
		gurtErr := fmt.Sprintf("Error fetching user associated with refresh token %s", refreshToken.Token) 
		respondWithError(w, http.StatusUnauthorized, gurtErr)
		return
	}
	tokenJWTString, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Duration(1) * time.Hour)
	if err != nil {
		jwtErr := fmt.Sprintf("Failed to create JWT token for user with id %s", user.ID) 
		respondWithError(w, http.StatusUnauthorized, jwtErr)
		return
	}

	type accessToken struct {
		Token string `json:"token"`
	}
	accessTokenPayload := accessToken{
		Token: tokenJWTString,
	}
	respondWithJSON(w, http.StatusOK, accessTokenPayload)
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	refreshToken, err := cfg.dbQueries.GetRefreshToken(r.Context(), tokenString)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = cfg.dbQueries.RevokeRefreshToken(r.Context(), refreshToken.Token)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Error loading environment variables: %s", err)
		return
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("Error opening Postgres db: %s", err)
		return
	}
	platformType := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")


	mux := http.NewServeMux()
	appHandler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	apiCfg := apiConfig{
		fileserverHits: atomic.Int32{},
		dbQueries: database.New(db),
		platformType: platformType,
		jwtSecret: jwtSecret,
	}
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(appHandler))
	hzh := http.HandlerFunc(healthzHandler)
	mux.Handle("GET /api/healthz", hzh)
	mh := http.HandlerFunc(apiCfg.metricsHandler)
	mux.Handle("GET /admin/metrics", mh)
	mrh := http.HandlerFunc(apiCfg.resetHandler)
	mux.Handle("POST /admin/reset", mrh)

	cch := http.HandlerFunc(apiCfg.createChirpHandler)
	mux.Handle("POST /api/chirps", cch)
	gcsh := http.HandlerFunc(apiCfg.getChirpsHandler)
	mux.Handle("GET /api/chirps", gcsh)
	gcidh := http.HandlerFunc(apiCfg.getChirpByIDHandler)
	mux.Handle("GET /api/chirps/{chirpID}", gcidh)
	dcidh := http.HandlerFunc(apiCfg.deleteChirpByIDHandler)
	mux.Handle("DELETE /api/chirps/{chirpID}", dcidh)
	
	cuh := http.HandlerFunc(apiCfg.createUserHandler)
	mux.Handle("POST /api/users", cuh)
	ulh := http.HandlerFunc(apiCfg.userLoginHandler)
	mux.Handle("POST /api/login", ulh)
	uuh := http.HandlerFunc(apiCfg.userUpdateHandler)
	mux.Handle("PUT /api/users", uuh)

	rfh := http.HandlerFunc(apiCfg.refreshHandler)
	mux.Handle("POST /api/refresh", rfh)
	rvh := http.HandlerFunc(apiCfg.revokeHandler)
	mux.Handle("POST /api/revoke", rvh)

	server := http.Server{
		Addr: ":8080",
		Handler: mux,
	}

	err = server.ListenAndServe()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
