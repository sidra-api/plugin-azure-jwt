package main

import (
	"log"
	"os"
	"net/http"

	"github.com/sidra-gateway/go-pdk/server"
	"github.com/sidra-api/plugin-azure-jwt/lib"
	
)

func main() {
	// Ambil nama plugin dari environment variable
	pluginName := os.Getenv("PLUGIN_NAME")
	if pluginName == "" {
		pluginName = "azure-jwt" // Default value jika tidak diatur
		log.Println("PLUGIN_NAME environment variable is not set, using default:", pluginName)
	}

	// Buat server plugin baru 
	jwtValidator := server.NewServer(pluginName, validateJWT)

	// Jalankan server plugin
	log.Println("Starting plugin server with name:", pluginName)
	if err := jwtValidator.Start(); err != nil {
		log.Fatalf("Failed to start the server: %v", err)
	}
}

// Fungsi handler untuk memvalidasi JWT dari request
func validateJWT(req server.Request) server.Response {
	// Ambil token dari header Authorization
	token := req.Headers["authorization"]
	if token == "" {
		log.Println("Authorization header is missing")
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Missing Authorization header",
		}
	}

	// Ambil JWKS URL dari environment variable
	jwksURL := os.Getenv("JWKS_URL")
	if jwksURL == "" {
		log.Println("JWKS_URL environment variable is not set")
		return server.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       "Environment variable JWKS_URL is not set",
		}
	}

	// Panggil fungsi VerifyJWT untuk memverifikasi token
	err := lib.VerifyJWT(token, jwksURL)
	if err != nil {
		log.Println("Invalid token :", err)
		return server.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       "Invalid token: " + err.Error(),
		}
	}

	// Jika token valid
	log.Println("JWT is valid")
	return server.Response{
		StatusCode: http.StatusOK,
		Body:       "JWT is valid",
	}
}