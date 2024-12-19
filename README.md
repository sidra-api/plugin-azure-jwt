# Azure JWT Validator Plugin for Sidra Api

This plugin validates JWT tokens using Azure's JSON Web Key Set (JWKS). It fetches the public key from a JWKS URL and verifies the token's signature. If the token is valid, it returns a successful response; otherwise, it returns an error response.

## Features

- Verifies JWT tokens by fetching public keys from a JWKS URL.
- Uses Azure's X.509 certificates for public key verification.
- Returns a `200 OK` response if the token is valid.
- Returns `401 Unauthorized` if the token is invalid.
- Returns `400 Bad Request` if the Authorization header is missing.

## Requirements

- Go 1.18 or higher
- Sidra Api plugin system
- Azure JWKS URL containing public keys for token validation

## Environment Variables

The plugin uses the following environment variables:

- `PLUGIN_NAME`: The name of the plugin (default: `azure-jwt-validator`).
- `JWKS_URL`: The URL to the Azure JWKS endpoint (e.g., `https://login.microsoftonline.com/{tenantId}/discovery/v2.0/keys`).

## Installation

To use this plugin, follow these steps:

1. Clone the repository:

    ```bash
    git clone https://github.com/sidra-api/plugin-azure-jwt.git
    ```

2. Navigate to the plugin directory:

    ```bash
    cd plugin-azure-jwt
    ```

3. Install the dependencies:

    ```bash
    go mod tidy
    ```

4. Build the plugin:

    ```bash
    go build -o azure-jwt-validator
    ```

5. Set the required environment variables:

    ```bash
    export PLUGIN_NAME="azure-jwt-validator"
    export JWKS_URL="https://login.microsoftonline.com/{tenantId}/discovery/v2.0/keys"
    ```

    Replace `{tenantId}` with your Azure tenant ID.

6. Run the plugin:

    ```bash
    ./azure-jwt-validator
    ```

## Configuration

- `PLUGIN_NAME`: Set this environment variable to specify the plugin name. It defaults to `azure-jwt-validator` if not set.
- `JWKS_URL`: This is the URL where the public keys (JWKS) are hosted by Azure. This must be set in your environment to ensure the plugin can fetch the public key for token validation.

## Usage

Once the plugin is running, it will listen for requests and validate the JWT tokens. Ensure that the request includes the Authorization header with the token to be validated.

### Example Request:

```bash
curl -X GET http://localhost:8080/some-api \
      -H "Authorization: Bearer {your-jwt-token}"
```

### Example Response:

**Valid JWT Token:**

```json
{
  "status": "OK",
  "message": "JWT is valid"
}
```

**Invalid JWT Token:**

```json
{
  "status": "Unauthorized",
  "message": "Invalid token: <error-message>"
}
```

## License

This project is licensed under the MIT License.

This `README.md` explains the purpose of the plugin, how to install and use it, the required environment variables, and how to configure it for use with Sidra Api.
