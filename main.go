package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"net/http"
	"os"

	"github.com/sidra-api/plugin-azure-jwt/lib"
	"github.com/sidra-gateway/go-pdk/server"
)

func main() {
	pluginName := os.Getenv("PLUGIN_NAME")
	log.Println("This is a test log entry")
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
	token := req.Headers["Authorization"]
	if token == "" {
		log.Println("Authorization header is missing")
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Missing Authorization header",
		}
	}
	token = token[7:] // Hapus "Bearer " dari
	log.Default().Println("Token:", token)
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
	tokenParsed, err := lib.VerifyJWT(token, jwksURL)
	if err != nil {
		log.Println("Invalid token :", err)
		return server.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       "Invalid token: " + err.Error(),
		}
	}

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("Failed to parse claims")
		return server.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       "Failed to parse claims",
		}
	}

	headers := make(map[string]string)
	for key, value := range claims {
		if key == "sub" {
			continue
		}
		switch v := value.(type) {
		case float64:
			headers[key] = fmt.Sprintf("%.0f", v)
		default:
			headers[key] = fmt.Sprintf("%v", value)
		}
	}

	log.Println("JWT is valid")
	return server.Response{
		StatusCode: http.StatusOK,
		Body:       "JWT is valid",
		Headers:    headers,
	}
}
