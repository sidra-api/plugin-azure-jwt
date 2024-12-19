package main

import (
	// "crypto/x509"
	// "encoding/base64"
	// "encoding/json"
	// "errors"
	"fmt"
	"net/http"

	"github.com/sidra-gateway/go-pdk/server"
	"github.com/sidra-api/plugin-azure-jwt/lib"
	
)

func main() {
	// Buat server plugin baru dengan nama "azure-jwt-validator"
	jwtValidator := server.NewServer("azure-jwt-validator", validateJWT)

	// Jalankan server plugin
	if err := jwtValidator.Start(); err != nil {
		panic(err)
	}
}

// Fungsi handler untuk memvalidasi JWT dari request
func validateJWT(req server.Request) server.Response {
	// Ambil token dari header Authorization
	token := req.Headers["authorization"]
	if token == "" {
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Missing Authorization header",
		}
	}

	// URL JWKS (untuk mendapatkan kunci publik)
	jwksURL := "https://login.microsoftonline.com/b636ee8f-7a9b-4c0d-91b1-f1a3ab14fce6/discovery/keys"

	// Panggil fungsi VerifyJWT untuk memverifikasi token
	err := lib.VerifyJWT(token, jwksURL)
	if err != nil {
		return server.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       "Invalid token: " + err.Error(),
		}
	}

	// Jika token valid
	return server.Response{
		StatusCode: http.StatusOK,
		Body:       "JWT is valid",
	}
}