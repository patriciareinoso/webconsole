// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package authentication

import (
	"fmt"

	//"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/omec-project/webconsole/backend/logger"
)

const (
	USER_ACCOUNT  = 0
	ADMIN_ACCOUNT = 1
)

// The middlewareContext type helps middleware receive and pass along information through the middleware chain.
type MiddlewareContext struct {
	ResponseStatusCode int
	JwtSecret          []byte
	FirstAccountIssued bool
}

type jwtGocertClaims struct {
	Username    string `json:"username"`
	Permissions int    `json:"permissions"`
	jwt.StandardClaims
}

// authMiddleware intercepts requests that need authorization to check if the user's token exists and is
// permitted to use the endpoint
func AuthMiddleware(ctx *MiddlewareContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.AuthLog.Errorln("INTERCEPTING CALLS")

		if !strings.HasPrefix(c.Request.URL.Path, "/account") {
			c.Next()
			return
		}

		if c.Request.Method == "POST" { //&& strings.HasSuffix(c.Request.URL.Path, "account") {
			firstAccountIssued, err := IsFirstAccountIssued()
			if err != nil {
				c.String(http.StatusInternalServerError, "error checking admin user account")
				c.Abort()
				return
			}
			if !firstAccountIssued {
				c.Next()
				return
			}
		}
		claims, err := getClaimsFromAuthorizationHeader(c.Request.Header.Get("Authorization"), ctx.JwtSecret)
		if err != nil {
			logger.AuthLog.Errorln(err)
			c.String(http.StatusUnauthorized, fmt.Sprintf("auth failed: %s", err.Error()))
			c.Abort()
			return
		}
		logger.AuthLog.Errorln(claims)
		if claims.Permissions == USER_ACCOUNT {
			requestAllowed, err := AllowRequest(claims, c.Request.Method, c.Request.URL.Path)
			if err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("error processing path: %s", err.Error()))
				c.Abort()
				return
			}
			if !requestAllowed {
				c.String(http.StatusForbidden, "forbidden")
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

func getClaimsFromAuthorizationHeader(header string, JwtSecret []byte) (*jwtGocertClaims, error) {
	if header == "" {
		return nil, fmt.Errorf("authorization header not found")
	}
	bearerToken := strings.Split(header, " ")
	if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
		return nil, fmt.Errorf("authorization header couldn't be processed. The expected format is 'Bearer <token>'")
	}
	claims, err := getClaimsFromJWT(bearerToken[1], JwtSecret)
	if err != nil {
		return nil, fmt.Errorf("token is not valid")
	}
	return claims, nil
}

func getClaimsFromJWT(bearerToken string, JwtSecret []byte) (*jwtGocertClaims, error) {
	claims := jwtGocertClaims{}
	token, err := jwt.ParseWithClaims(bearerToken, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return JwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return &claims, nil
}

func AllowRequest(claims *jwtGocertClaims, method, path string) (bool, error) {
	allowedPaths := []struct {
		method, pathRegex string
	}{
		{"GET", `/account\/(\w+)$`},
		{"POST", `/account\/(\w+)\/change_password$`},
	}
	for _, pr := range allowedPaths {
		regex, err := regexp.Compile(pr.pathRegex)
		if err != nil {
			return false, fmt.Errorf("regex couldn't compile: %s", err)
		}
		matches := regex.FindStringSubmatch(path)
		if len(matches) > 0 && method == pr.method {
			if matches[1] == claims.Username {
				return true, nil
			}
			return false, nil
		}
	}
	return false, nil
}
