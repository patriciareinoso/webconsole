// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package authentication

import (
	"fmt"
	//"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"github.com/omec-project/webconsole/backend/logger"

	"github.com/golang-jwt/jwt"
)

const (
	USER_ACCOUNT  = 0
	ADMIN_ACCOUNT = 1
)

type middleware func(http.Handler) http.Handler

// The middlewareContext type helps middleware receive and pass along information through the middleware chain.
type middlewareContext struct {
	responseStatusCode int
	jwtSecret          []byte
	firstAccountIssued bool
}

type jwtGocertClaims struct {
	Username    string `json:"username"`
	Permissions int    `json:"permissions"`
	jwt.StandardClaims
}


// authMiddleware intercepts requests that need authorization to check if the user's token exists and is
// permitted to use the endpoint
func authMiddleware(ctx *middlewareContext) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "accounts") && !ctx.firstAccountIssued {
				next.ServeHTTP(w, r)
				if strings.HasPrefix(strconv.Itoa(ctx.responseStatusCode), "2") {
					ctx.firstAccountIssued = true
				}
				return
			}
			claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), ctx.jwtSecret)
			if err != nil {
				logger.AuthLog.Errorln(err)
        		//c.String(http.StatusUnauthorized, fmt.Sprintf("auth failed: %s", err.Error()))
				//logErrorAndWriteResponse(fmt.Sprintf("auth failed: %s", err.Error()), http.StatusUnauthorized, w)
				return
			}
			if claims.Permissions == USER_ACCOUNT {
				requestAllowed, err := AllowRequest(claims, r.Method, r.URL.Path)
				if err != nil {
					//c.String(http.StatusInternalServerError, fmt.Sprintf("error processing path: %s", err.Error()))
					//logErrorAndWriteResponse(fmt.Sprintf("error processing path: %s", err.Error()), http.StatusInternalServerError, w)
					return
				}
				if !requestAllowed {
					//c.String(http.StatusForbidden, "forbidden")
					//logErrorAndWriteResponse("forbidden", http.StatusForbidden, w)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func getClaimsFromAuthorizationHeader(header string, jwtSecret []byte) (*jwtGocertClaims, error) {
	if header == "" {
		return nil, fmt.Errorf("authorization header not found")
	}
	bearerToken := strings.Split(header, " ")
	if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
		return nil, fmt.Errorf("authorization header couldn't be processed. The expected format is 'Bearer <token>'")
	}
	claims, err := getClaimsFromJWT(bearerToken[1], jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("token is not valid: %s", err)
	}
	return claims, nil
}

// AllowRequest looks at the user data to determine the following things:
// The first question is "Is this user trying to access a path that's restricted?"
//
// There are two types of restricted paths: admin only paths that only admins can access, and self authorized paths,
// which users are allowed to use only if they are taking an action on their own user ID. The second question is
// "If the path requires an ID, is the user attempting to access their own ID?"
//
// For all endpoints and permission permutations, there are only 2 cases when users are allowed to use endpoints:
// If the URL path is not restricted to admins
// If the URL path is restricted to self authorized endpoints, and the user is taking action with their own ID
// This function validates that the user the with the given claims is allowed to use the endpoints by passing the above checks.
func AllowRequest(claims *jwtGocertClaims, method, path string) (bool, error) {
	restrictedPaths := []struct {
		method, pathRegex     string
		SelfAuthorizedAllowed bool
	}{
		{"POST", `accounts$`, false},
		{"GET", `accounts$`, false},
		{"DELETE", `accounts\/(\d+)$`, false},
		{"GET", `accounts\/(\d+)$`, true},
		{"POST", `accounts\/(\d+)\/change_password$`, true},
	}
	for _, pr := range restrictedPaths {
		regexChallenge, err := regexp.Compile(pr.pathRegex)
		if err != nil {
			return false, fmt.Errorf("regex couldn't compile: %s", err)
		}
		matches := regexChallenge.FindStringSubmatch(path)
		restrictedPathMatchedToRequestedPath := len(matches) > 0 && method == pr.method
		if !restrictedPathMatchedToRequestedPath {
			continue
		}
		if !pr.SelfAuthorizedAllowed {
			return false, nil
		}
		matchedUsername:=matches[1]

		var requestedUsernameMatchesTheClaimant bool
		if matchedUsername == claims.Username {
			requestedUsernameMatchesTheClaimant = true
		}
		UsernameRequiredForPath := len(matches) > 1
		if UsernameRequiredForPath && !requestedUsernameMatchesTheClaimant {
			return false, nil
		}
		return true, nil
	}
	return true, nil
}

func getClaimsFromJWT(bearerToken string, jwtSecret []byte) (*jwtGocertClaims, error) {
	claims := jwtGocertClaims{}
	token, err := jwt.ParseWithClaims(bearerToken, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return &claims, nil
}
