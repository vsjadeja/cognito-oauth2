# cognito-oauth2


Small example service demonstrating OAuth2 authentication using AWS Cognito (with Google as an identity provider).

This repository contains a minimal Go application that shows how to integrate Cognito OAuth2 flows for user login and token handling.

Important: this is a backend-only service and does not include a built-in Cognito UI. The project exposes HTTP endpoints to start the OAuth2 flow and receive callbacks; use a browser, an API client (Postman), or curl to interact with those endpoints.

## Features

- Start an OAuth2 login flow to Cognito (no built-in UI)
- Handle the authorization callback and exchange code for tokens

## Prerequisites

- Go 1.20+ installed
- An AWS Cognito User Pool with an App Client configured for OAuth2
- (Optional) Google as an external identity provider configured in Cognito

## Environment variables

Set these environment variables before running the app (replace values with your configuration):

- COGNITO_DOMAIN - your Cognito domain (e.g. `your-domain.auth.us-east-1.amazoncognito.com`)
- COGNITO_CLIENT_ID - App client ID
- COGNITO_CLIENT_SECRET - App client secret (if applicable)

Example (bash):

```bash
export COGNITO_CLIENT_ID="<your-client-id>"
export COGNITO_CLIENT_SECRET="<your-secret>"
export GOOGLE_CLIENT_ID="<your-google-client-id>"
export APPLE_CLIENT_ID="<your-apple-clinet-id>"

```

## Build & Run

Run locally with:

```bash
go run main.go
```

Or build a binary:

```bash
go build -o cognito-oauth2
./cognito-oauth2
```

The app will start an HTTP server (see `main.go`) and expose endpoints to begin the OAuth flow and receive the callback.

## Notes

-- This is a small demo. Do not use the code as-is in production without adding proper session management, secure storage for secrets, TLS, CSRF protection, and input validation. If you need a user-facing UI, build a separate frontend that calls these endpoints or integrate the flows into your existing app.

## License

MIT
