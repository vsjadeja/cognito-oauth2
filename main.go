package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"google.golang.org/api/idtoken"
)

type LoginRequest struct {
	IDToken string `json:"id_token"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

var (
	cognitoClient  *cognito.Client
	userPoolID     string
	clientID       string
	googleClientID string
)

type AppleLoginRequest struct {
	IDToken string `json:"id_token"`
}

type AppleLoginResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Message      string `json:"message,omitempty"`
}

var (
	cognitoClientApple *cognito.Client
	userPoolIDApple    string
	clientIDApple      string
)

func initApple() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		panic(err)
	}
	cognitoClientApple = cognito.NewFromConfig(cfg)
	userPoolIDApple = os.Getenv("COGNITO_USER_POOL_ID")
	clientIDApple = os.Getenv("COGNITO_APP_CLIENT_ID")
}

// fetch Apple public keys
func fetchAppleJWKSet() (jwk.Set, error) {
	set, err := jwk.Fetch(context.Background(), "https://appleid.apple.com/auth/keys")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Apple JWKs: %w", err)
	}
	return set, nil
}

// verify Apple ID token
func verifyAppleIDToken(tokenString string, audience string) (jwt.MapClaims, error) {
	set, err := fetchAppleJWKSet()
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		keyID, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid header in token")
		}

		key, found := set.LookupKeyID(keyID)
		if !found {
			return nil, fmt.Errorf("no matching JWK for kid: %s", keyID)
		}

		var pubkey interface{}
		if err := key.Raw(&pubkey); err != nil {
			return nil, err
		}
		return pubkey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("apple token validation failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Check expiry and audience
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return nil, errors.New("token expired")
		}
	}
	if aud, ok := claims["aud"].(string); ok && aud != audience {
		return nil, fmt.Errorf("invalid audience: %s", aud)
	}

	return claims, nil
}

func loginWithAppleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	w.Header().Set("Content-Type", "application/json")

	var req AppleLoginRequest
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	claims, err := verifyAppleIDToken(req.IDToken, os.Getenv("APPLE_CLIENT_ID"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "apple token verification failed: %v"}`, err), http.StatusUnauthorized)
		return
	}

	email := fmt.Sprintf("%v", claims["email"])
	fmt.Printf("✅ Verified Apple login for: %s\n", email)

	// Optionally integrate with Cognito
	resp, err := cognitoClientApple.InitiateAuth(ctx, &cognito.InitiateAuthInput{
		AuthFlow: "CUSTOM_AUTH",
		ClientId: aws.String(clientIDApple),
		AuthParameters: map[string]string{
			"USERNAME": email,
		},
	})
	if err != nil {
		json.NewEncoder(w).Encode(AppleLoginResponse{
			Message: fmt.Sprintf("Apple login verified for %s (Cognito not configured)", email),
		})
		return
	}

	json.NewEncoder(w).Encode(AppleLoginResponse{
		AccessToken:  aws.ToString(resp.AuthenticationResult.AccessToken),
		IDToken:      aws.ToString(resp.AuthenticationResult.IdToken),
		RefreshToken: aws.ToString(resp.AuthenticationResult.RefreshToken),
	})
}

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		panic(err)
	}
	cognitoClient = cognito.NewFromConfig(cfg)

	userPoolID = os.Getenv("COGNITO_USER_POOL_ID")
	clientID = os.Getenv("COGNITO_APP_CLIENT_ID")
	googleClientID = os.Getenv("GOOGLE_CLIENT_ID")

	initApple()
}

func loginWithGoogleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	var req LoginRequest
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// 1️⃣ Verify Google token
	payload, err := idtoken.Validate(ctx, req.IDToken, googleClientID)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid google token: %v", err), http.StatusUnauthorized)
		return
	}

	email := payload.Claims["email"].(string)

	// 2️⃣ Exchange token with Cognito (using OAuth2 IdP)
	resp, err := cognitoClient.InitiateAuth(ctx, &cognito.InitiateAuthInput{
		AuthFlow: "USER_SRP_AUTH",
		ClientId: aws.String(clientID),
		AuthParameters: map[string]string{
			"IDENTITY_PROVIDER": "Google",
			"USERNAME":          email,
			"ID_TOKEN":          req.IDToken,
		},
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("cognito auth error: %v", err), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(LoginResponse{
		AccessToken:  aws.ToString(resp.AuthenticationResult.AccessToken),
		IDToken:      aws.ToString(resp.AuthenticationResult.IdToken),
		RefreshToken: aws.ToString(resp.AuthenticationResult.RefreshToken),
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/loginWithGoogle", loginWithGoogleHandler)
	mux.HandleFunc("/auth/loginWithApple", loginWithAppleHandler)

	fmt.Println("🚀 Server running on http://localhost:3333")
	if err := http.ListenAndServe(":3333", mux); err != nil {
		fmt.Printf("❌ Server stopped: %v\n", err)
	}
}
