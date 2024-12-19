package lib

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type JWK struct {
	Kid string   `json:"kid"` // Key ID, digunakan untuk mencocokkan kunci publik
	X5c []string `json:"x5c"` // Sertifikat dalam format base64
}

type JWKS struct {
	Keys []JWK `json:"keys"` // Daftar semua kunci publik dalam JWKS
}

// Fungsi utama untuk memverifikasi JWT
func VerifyJWT(tokenString, jwksURL string) error {
	// Pisahkan JWT menjadi tiga bagian (header, payload, signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return errors.New("invalid JWT format")
	}

	// Decode bagian header JWT dari base64
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("failed to decode JWT header")
	}

	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return errors.New("failed to parse JWT header")
	}

	// Get public key by kid
	publicKey, err := getPublicKey(header.Kid, jwksURL)
	if err != nil {
		return err
	}

	// Verifikasi JWT menggunakan kunci publik
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}
	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return errors.New("failed to verify JWT: " + err.Error())
	}

	// Pastikan token valid
	if !token.Valid {
		return errors.New("invalid JWT token")
	}

	return nil
}

// Ambil kunci publik dari URL JWKS berdasarkan Key ID (kid)
func getPublicKey(kid, jwksURL string) (interface{}, error) {
	// Ambil JWKS dari URL yang diberikan
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse respons menjadi struktur JWKS
	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	// Find public key by kid
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			// Decode sertifikat dari base64
			certData, err := base64.StdEncoding.DecodeString(key.X5c[0])
			if err != nil {
				return nil, err
			}

			// Parse sertifikat menjadi kunci publik
			cert, err := x509.ParseCertificate(certData)
			if err != nil {
				return nil, err
			}

			return cert.PublicKey, nil
		}
	}

	return nil, errors.New("key not found")
}
