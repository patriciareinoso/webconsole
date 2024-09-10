// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package authentication

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/webconsole/dbadapter"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

type MockMongoClientEmptyDB struct {
	dbadapter.DBInterface
}

type MockMongoClientDBError struct {
	dbadapter.DBInterface
}

type MockMongoClientInvalidUser struct {
	dbadapter.DBInterface
}

type MockMongoClientSuccess struct {
	dbadapter.DBInterface
}

type MockMongoClientRegularUser struct {
	dbadapter.DBInterface
}

func hashPassword(password string) string {
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed)
}

func (m *MockMongoClientEmptyDB) RestfulAPIGetOne(collName string, filter bson.M) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func (m *MockMongoClientEmptyDB) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	return results, nil
}

func (m *MockMongoClientEmptyDB) RestfulAPIPost(collName string, filter bson.M, postData map[string]interface{}) (bool, error) {
	return true, nil
}

func (m *MockMongoClientDBError) RestfulAPIGetOne(coll string, filter bson.M) (map[string]interface{}, error) {
	return nil, errors.New("DB error")
}

func (m *MockMongoClientDBError) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
	return nil, errors.New("DB error")
}

func (m *MockMongoClientDBError) RestfulAPIPost(collName string, filter bson.M, postData map[string]interface{}) (bool, error) {
	return false, errors.New("DB error")
}

func (m *MockMongoClientInvalidUser) RestfulAPIGetOne(collName string, filter bson.M) (map[string]interface{}, error) {
	rawUser := map[string]interface{}{
		"username":    "johndoe",
		"password":    1234,
		"permissions": 0,
	}
	return rawUser, nil
}
func (m *MockMongoClientInvalidUser) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
	rawUsers := []map[string]interface{}{
		{"username": "johndoe", "password": 1234, "permissions": 0},
		{"username": "janedoe", "password": hashPassword("password123"), "permissions": 1},
	}
	return rawUsers, nil
}

func (m *MockMongoClientSuccess) RestfulAPIGetOne(coll string, filter bson.M) (map[string]interface{}, error) {
	rawUser := map[string]interface{}{
		"username": "janedoe", "password": hashPassword("password123"), "permissions": 1,
	}
	return rawUser, nil
}

func (m *MockMongoClientSuccess) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
	rawUsers := []map[string]interface{}{
		{"username": "johndoe", "password": hashPassword("password123"), "permissions": 0},
		{"username": "janedoe", "password": hashPassword("password123"), "permissions": 1},
	}
	return rawUsers, nil
}

func (m *MockMongoClientSuccess) RestfulAPIPost(collName string, filter bson.M, postData map[string]interface{}) (bool, error) {
	return true, nil
}

func (m *MockMongoClientRegularUser) RestfulAPIGetOne(coll string, filter bson.M) (map[string]interface{}, error) {
	rawUser := map[string]interface{}{
		"username": "janedoe", "password": hashPassword("password123"), "permissions": 0,
	}
	return rawUser, nil
}

func (m *MockMongoClientRegularUser) RestfulAPIDeleteOne(collName string, filter bson.M) error {
	return nil
}

func mockGeneratePassword() (string, error) {
	return "ValidPass123!", nil
}

func mockGeneratePasswordFailure() (string, error) {
	return "", errors.New("password generation failed")
}

var mockGenerateJWT = func(username string, permissions int, jwtSecret []byte) (string, error) {
	return "mocked.jwt.token", nil
}

func TestMiddleware_NoHeaderRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	dbadapter.CommonDBClient = &MockMongoClientSuccess{}
	mockJWTSecret := []byte("mockSecret")
	ctx := &MiddlewareContext{JwtSecret: mockJWTSecret}
	router.Use(AuthMiddleware(ctx))
	router.GET("/account", GetUserAccounts(mockJWTSecret))
	router.GET("/account/:username", GetUserAccount(mockJWTSecret))
	router.POST("/account", PostUserAccount(mockJWTSecret))
	router.POST("/account/:username/change_password", ChangeUserAccountPasssword(mockJWTSecret))
	router.DELETE("/account/:username", DeleteUserAccount(mockJWTSecret))

	testCases := []struct {
		name   string
		method string
		url    string
	}{
		{
			name:   "GetUserAccount",
			method: http.MethodGet,
			url:    "/account/janedoe",
		},
		{
			name:   "GetUserAccounts",
			method: http.MethodGet,
			url:    "/account",
		},
		{
			name:   "PostSecondUserAccount",
			method: http.MethodPost,
			url:    "/account",
		},
		{
			name:   "DeleteUserAccount",
			method: http.MethodDelete,
			url:    "/account/janedoe",
		},
		{
			name:   "ChangePassword",
			method: http.MethodPost,
			url:    "/account/janedoe/change_password",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, tc.url, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			expectedCode := http.StatusUnauthorized
			expectedBody := `{"error":"auth failed: authorization header not found"}`
			if expectedCode != w.Code {
				t.Errorf("Expected `%v`, got `%v`", expectedCode, w.Code)
			}
			if w.Body.String() != expectedBody {
				t.Errorf("Expected `%v`, got `%v`", expectedBody, w.Body.String())
			}
		})
	}
}

func TestMiddleware_InvalidHeaderRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dbadapter.CommonDBClient = &MockMongoClientSuccess{}
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	ctx := &MiddlewareContext{JwtSecret: mockJWTSecret}
	router.Use(AuthMiddleware(ctx))
	router.GET("/account", GetUserAccounts(mockJWTSecret))
	router.GET("/account/:username", GetUserAccount(mockJWTSecret))
	router.POST("/account", PostUserAccount(mockJWTSecret))
	router.POST("/account/:username/change_password", ChangeUserAccountPasssword(mockJWTSecret))
	router.DELETE("/account/:username", DeleteUserAccount(mockJWTSecret))

	testCases := []struct {
		name         string
		method       string
		url          string
		invalidToken string
		expectedBody string
	}{
		{
			name:         "GetUserAccount_InvalidFormat",
			method:       http.MethodGet,
			url:          "/account/janedoe",
			invalidToken: "Bearer",
			expectedBody: `{"error":"auth failed: authorization header couldn't be processed. The expected format is 'Bearer token'"}`,
		},
		{
			name:         "GetUserAccounts_InvalidFormat",
			method:       http.MethodGet,
			url:          "/account",
			invalidToken: "Bear s",
			expectedBody: `{"error":"auth failed: authorization header couldn't be processed. The expected format is 'Bearer token'"}`,
		},
		{
			name:         "CreateSecondUserAccount_InvalidFormat",
			method:       http.MethodPost,
			url:          "/account",
			invalidToken: "Bearer",
			expectedBody: `{"error":"auth failed: authorization header couldn't be processed. The expected format is 'Bearer token'"}`,
		},
		{
			name:         "DeleteUserAccount_InvalidFormat",
			method:       http.MethodDelete,
			url:          "/account/janedoe",
			invalidToken: "Bearer",
			expectedBody: `{"error":"auth failed: authorization header couldn't be processed. The expected format is 'Bearer token'"}`,
		},
		{
			name:         "ChangePassword_InvalidFormat",
			method:       http.MethodPost,
			url:          "/account/janedoe/change_password",
			invalidToken: "Bearer",
			expectedBody: `{"error":"auth failed: authorization header couldn't be processed. The expected format is 'Bearer token'"}`,
		},
		{
			name:         "GetUserAccount_InvalidToken",
			method:       http.MethodGet,
			url:          "/account/janedoe",
			invalidToken: "Bearer sometoken",
			expectedBody: `{"error":"auth failed: token is not valid"}`,
		},
		{
			name:         "GetUserAccounts_InvalidToken",
			method:       http.MethodGet,
			url:          "/account",
			invalidToken: "Bearer sometoken",
			expectedBody: `{"error":"auth failed: token is not valid"}`,
		},
		{
			name:         "CreateSecondUserAccount_InvalidToken",
			method:       http.MethodPost,
			url:          "/account",
			invalidToken: "Bearer sometoken",
			expectedBody: `{"error":"auth failed: token is not valid"}`,
		},
		{
			name:         "DeleteUserAccount_InvalidToken",
			method:       http.MethodDelete,
			url:          "/account/janedoe",
			invalidToken: "Bearer token",
			expectedBody: `{"error":"auth failed: token is not valid"}`,
		},
		{
			name:         "ChangePassword_InvalidToken",
			method:       http.MethodPost,
			url:          "/account/janedoe/change_password",
			invalidToken: "Bearer mytoken",
			expectedBody: `{"error":"auth failed: token is not valid"}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, tc.url, nil)
			req.Header.Set("Authorization", tc.invalidToken)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			expectedCode := http.StatusUnauthorized

			if expectedCode != w.Code {
				t.Errorf("Expected `%v`, got `%v`", expectedCode, w.Code)
			}
			if w.Body.String() != tc.expectedBody {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedBody, w.Body.String())
			}
		})
	}
}

func TestGetUserAccounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	ctx := &MiddlewareContext{JwtSecret: mockJWTSecret}
	router.Use(AuthMiddleware(ctx))
	router.GET("/account", GetUserAccounts(mockJWTSecret))

	testCases := []struct {
		name         string
		username     string
		permissions  int
		dbAdapter    dbadapter.DBInterface
		expectedCode int
		expectedBody string
	}{
		{
			name:         "RegularUser_IsNotAllowedToGetUserAccounts",
			username:     "someusername",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusForbidden,
			expectedBody: `{"error":"forbidden"}`,
		},
		{
			name:         "AdminUser_DBError",
			username:     "someusername",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientDBError{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorRetrieveUserAccounts),
		},
		{
			name:         "AdminUser_OneInvalidUser",
			username:     "someusername",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientInvalidUser{},
			expectedCode: http.StatusOK,
			expectedBody: `[{"username":"janedoe","permissions":1}]`,
		},
		{
			name:         "AdminUser_NoUsers",
			username:     "someusername",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientEmptyDB{},
			expectedCode: http.StatusOK,
			expectedBody: "[]",
		},
		{
			name:         "AdminUser_SuccessManyUsers",
			username:     "someusername",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusOK,
			expectedBody: `[{"username":"johndoe","permissions":0},{"username":"janedoe","permissions":1}]`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbadapter.CommonDBClient = tc.dbAdapter
			jwtToken, _ := generateJWT(tc.username, tc.permissions, mockJWTSecret)
			validToken := "Bearer " + jwtToken
			req, _ := http.NewRequest(http.MethodGet, "/account", nil)
			req.Header.Set("Authorization", validToken)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if tc.expectedCode != w.Code {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedCode, w.Code)
			}
			if w.Body.String() != tc.expectedBody {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedBody, w.Body.String())
			}
		})
	}
}

func TestGetUserAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	ctx := &MiddlewareContext{JwtSecret: mockJWTSecret}
	router.Use(AuthMiddleware(ctx))
	router.GET("/account/:username", GetUserAccount(mockJWTSecret))

	testCases := []struct {
		name         string
		username     string
		permissions  int
		dbAdapter    dbadapter.DBInterface
		expectedCode int
		expectedBody string
	}{
		{
			name:         "RegularUser_GetOwnUserAccount",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusOK,
			expectedBody: `{"username":"janedoe","permissions":1}`,
		},
		{
			name:         "AdminUser_GetOwnUserAccount",
			username:     "janedoe",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusOK,
			expectedBody: `{"username":"janedoe","permissions":1}`,
		},
		{
			name:         "RegularUser_GetOtherUserAccount",
			username:     "someuser",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusForbidden,
			expectedBody: `{"error":"forbidden"}`,
		},
		{
			name:         "AdminUser_GetOtherUserAccount",
			username:     "someuser",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusOK,
			expectedBody: `{"username":"janedoe","permissions":1}`,
		},
		{
			name:         "RegularUser_DBError",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientDBError{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorRetrieveUserAccount),
		},
		{
			name:         "AdminUser_DBError",
			username:     "someuser",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientDBError{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorRetrieveUserAccount),
		},
		{
			name:         "RegularUser_UserNotFound",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientEmptyDB{},
			expectedCode: http.StatusNotFound,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorUsernameNotFound),
		},
		{
			name:         "AdminUser_UserNotFound",
			username:     "someuser",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientEmptyDB{},
			expectedCode: http.StatusNotFound,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorUsernameNotFound),
		},
		{
			name:         "RegularUser_InvalidUser",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientInvalidUser{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorRetrieveUserAccount),
		},
		{
			name:         "AdminUser_InvalidUser",
			username:     "someuser",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientInvalidUser{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorRetrieveUserAccount),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbadapter.CommonDBClient = tc.dbAdapter
			jwtToken, _ := generateJWT(tc.username, tc.permissions, mockJWTSecret)
			validToken := "Bearer " + jwtToken
			req, _ := http.NewRequest(http.MethodGet, "/account/janedoe", nil)
			req.Header.Set("Authorization", validToken)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if tc.expectedCode != w.Code {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedCode, w.Code)
			}
			if w.Body.String() != tc.expectedBody {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedBody, w.Body.String())
			}
		})
	}
}

func TestPostUserAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	ctx := &MiddlewareContext{JwtSecret: mockJWTSecret}
	router.Use(AuthMiddleware(ctx))
	router.POST("/account", PostUserAccount(mockJWTSecret))

	testCases := []struct {
		name                 string
		username             string
		permissions          int
		dbAdapter            dbadapter.DBInterface
		generatePasswordMock func() (string, error)
		inputData            string
		expectedCode         int
		expectedBody         string
	}{
		{
			name:                 "RegularUser_CreateSecondUser",
			username:             "someusername",
			permissions:          USER_ACCOUNT,
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"username": "adminadmin"}`,
			expectedCode:         http.StatusForbidden,
			expectedBody:         `{"error":"forbidden"}`,
		},
		{
			name:                 "AdminUser_CreateSecondUserWithoutUsername",
			username:             "someusername",
			permissions:          ADMIN_ACCOUNT,
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            "{}",
			expectedCode:         http.StatusBadRequest,
			expectedBody:         fmt.Sprintf(`{"error":"%s"}`, errorMissingUsername),
		},
		{
			name:                 "AdminUser_CreateSecondUserWithoutPassword",
			username:             "someusername",
			permissions:          ADMIN_ACCOUNT,
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"username": "adminadmin"}`,
			expectedCode:         http.StatusCreated,
			expectedBody:         `{"password":"ValidPass123!"}`,
		},
		{
			name:                 "AdminUser_CreateSecondUserWithPassword",
			username:             "someusername",
			permissions:          ADMIN_ACCOUNT,
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"username": "adminadmin", "password" : "Admin1234"}`,
			expectedCode:         http.StatusCreated,
			expectedBody:         `{}`,
		},
		{
			name:                 "AdminUser_DBError",
			username:             "someusername",
			permissions:          ADMIN_ACCOUNT,
			dbAdapter:            &MockMongoClientDBError{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"username": "adminadmin", "password" : "Admin1234"}`,
			expectedCode:         http.StatusInternalServerError,
			expectedBody:         `{"error":"failed to authorize user account creation"}`,
		},
		{
			name:                 "AdminUser_InvalidPassword",
			username:             "someusername",
			permissions:          ADMIN_ACCOUNT,
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"username": "adminadmin", "password" : "1234"}`,
			expectedCode:         http.StatusBadRequest,
			expectedBody:         fmt.Sprintf(`{"error":"%s"}`, errorInvalidPassword),
		},
		{
			name:                 "AdminUser_ErrorGeneratingPassword",
			username:             "someusername",
			permissions:          ADMIN_ACCOUNT,
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePasswordFailure,
			inputData:            `{"username": "adminadmin"}`,
			expectedCode:         http.StatusInternalServerError,
			expectedBody:         fmt.Sprintf(`{"error":"%s"}`, errorCreateUserAccount),
		},
		{
			name:                 "AdminUser_InvalidJsonProvided",
			username:             "someusername",
			permissions:          ADMIN_ACCOUNT,
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"username": "adminadmin", "password": 1234}`,
			expectedCode:         http.StatusBadRequest,
			expectedBody:         fmt.Sprintf(`{"error":"%s"}`, errorInvalidDataProvided),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			generatePassword = tc.generatePasswordMock
			dbadapter.CommonDBClient = tc.dbAdapter
			jwtToken, _ := generateJWT(tc.username, tc.permissions, mockJWTSecret)
			validToken := "Bearer " + jwtToken
			req, _ := http.NewRequest(http.MethodPost, "/account", strings.NewReader(tc.inputData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", validToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tc.expectedCode != w.Code {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedCode, w.Code)
			}
			if w.Body.String() != tc.expectedBody {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedBody, w.Body.String())
			}
		})
	}
}

func TestPostUserAccount_CreateFirstUserWithoutHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dbadapter.CommonDBClient = &MockMongoClientEmptyDB{}
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	ctx := &MiddlewareContext{JwtSecret: mockJWTSecret}
	router.Use(AuthMiddleware(ctx))
	router.POST("/account", PostUserAccount(mockJWTSecret))
	req, _ := http.NewRequest(http.MethodPost, "/account", strings.NewReader(`{"username": "adminadmin", "password":"ValidPass123!"}`))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	expectedCode := http.StatusCreated
	expectedBody := "{}"
	if expectedCode != w.Code {
		t.Errorf("Expected `%v`, got `%v`", expectedCode, w.Code)
	}
	if w.Body.String() != expectedBody {
		t.Errorf("Expected `%v`, got `%v`", expectedBody, w.Body.String())
	}
}

func TestDeleteUserAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	ctx := &MiddlewareContext{JwtSecret: mockJWTSecret}
	router.Use(AuthMiddleware(ctx))
	router.DELETE("/account/:username", DeleteUserAccount(mockJWTSecret))

	testCases := []struct {
		name         string
		username     string
		permissions  int
		dbAdapter    dbadapter.DBInterface
		expectedCode int
		expectedBody string
	}{
		{
			name:         "RegularUser_DeleteAnotherUser",
			username:     "someuser",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientRegularUser{},
			expectedCode: http.StatusForbidden,
			expectedBody: `{"error":"forbidden"}`,
		},
		{
			name:         "RegularUser_DeleteThemselves",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientRegularUser{},
			expectedCode: http.StatusForbidden,
			expectedBody: `{"error":"forbidden"}`,
		},
		{
			name:         "AdminUser_DeleteRegularUser",
			username:     "someuser",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientRegularUser{},
			expectedCode: http.StatusOK,
			expectedBody: "{}",
		},
		{
			name:         "AdminUser_DeleteAdminUser",
			username:     "janedoe",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorDeleteAdminAccount),
		},
		{
			name:         "AdminUser_DeleteInvalidUser",
			username:     "someuser",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientInvalidUser{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorRetrieveUserAccount),
		},
		{
			name:         "AdminUser_UserNotFound",
			username:     "someuser",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientEmptyDB{},
			expectedCode: http.StatusNotFound,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorUsernameNotFound),
		},
		{
			name:         "AdminUser_DBError",
			username:     "someuser",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientDBError{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorRetrieveUserAccount),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbadapter.CommonDBClient = tc.dbAdapter
			req, _ := http.NewRequest(http.MethodDelete, "/account/janedoe", nil)
			jwtToken, _ := generateJWT(tc.username, tc.permissions, mockJWTSecret)
			validToken := "Bearer " + jwtToken
			req.Header.Set("Authorization", validToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tc.expectedCode != w.Code {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedCode, w.Code)
			}
			if w.Body.String() != tc.expectedBody {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedBody, w.Body.String())
			}
		})
	}
}

func TestChangePassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	ctx := &MiddlewareContext{JwtSecret: mockJWTSecret}
	router.Use(AuthMiddleware(ctx))
	router.POST("/account/:username/change_password", ChangeUserAccountPasssword(mockJWTSecret))

	testCases := []struct {
		name         string
		username     string
		permissions  int
		dbAdapter    dbadapter.DBInterface
		inputData    string
		expectedCode int
		expectedBody string
	}{
		{
			name:         "AdminUser_ChangeTheirOwnPassword",
			username:     "janedoe",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			inputData:    `{"password": "Admin1234"}`,
			expectedCode: http.StatusOK,
			expectedBody: "{}",
		},
		{
			name:         "RegularUser_ChangeTheirOwnPassword",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			inputData:    `{"password": "Admin1234"}`,
			expectedCode: http.StatusOK,
			expectedBody: "{}",
		},
		{
			name:         "RegularUser_ChangeOtherUserPassword",
			username:     "otheruser",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			inputData:    `{"password": "Admin1234"}`,
			expectedCode: http.StatusForbidden,
			expectedBody: `{"error":"forbidden"}`,
		},
		{
			name:         "AdminUser_ChangeOtherUserPassword",
			username:     "adminuser",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientSuccess{},
			inputData:    `{"password": "Admin1234"}`,
			expectedCode: http.StatusOK,
			expectedBody: "{}",
		},
		{
			name:         "AdminUser_DBError",
			username:     "janedoe",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    &MockMongoClientDBError{},
			inputData:    `{"password": "Admin1234"}`,
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorUpdateUserAccount),
		},
		{
			name:         "RegularUser_DBError",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    &MockMongoClientDBError{},
			inputData:    `{"password": "Admin1234"}`,
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorUpdateUserAccount),
		},
		{
			name:         "AdminUser_InvalidPassword",
			username:     "janedoe",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    nil,
			inputData:    `{"password": "1234"}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorInvalidPassword),
		},
		{
			name:         "RegularUser_InvalidPassword",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    nil,
			inputData:    `{"password": "1234"}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorInvalidPassword),
		},
		{
			name:         "AdminUser_NoPasswordProvided",
			username:     "janedoe",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    nil,
			inputData:    `{}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorMissingPassword),
		},
		{
			name:         "RegularUser_NoPasswordProvided",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    nil,
			inputData:    `{}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorMissingPassword),
		},
		{
			name:         "AdminUser_InvalidData",
			username:     "janedoe",
			permissions:  ADMIN_ACCOUNT,
			dbAdapter:    nil,
			inputData:    `{"password": 1234}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorInvalidDataProvided),
		},
		{
			name:         "RegularUser_InvalidData",
			username:     "janedoe",
			permissions:  USER_ACCOUNT,
			dbAdapter:    nil,
			inputData:    `{"password": 1234}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorInvalidDataProvided),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbadapter.CommonDBClient = tc.dbAdapter
			req, _ := http.NewRequest(http.MethodPost, "/account/janedoe/change_password", strings.NewReader(tc.inputData))
			jwtToken, _ := generateJWT(tc.username, tc.permissions, mockJWTSecret)
			validToken := "Bearer " + jwtToken
			req.Header.Set("Authorization", validToken)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if tc.expectedCode != w.Code {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedCode, w.Code)
			}
			if w.Body.String() != tc.expectedBody {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedBody, w.Body.String())
			}
		})
	}
}

func TestLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	ctx := &MiddlewareContext{JwtSecret: mockJWTSecret}
	router.Use(AuthMiddleware(ctx))
	router.POST("/login", Login(mockJWTSecret))
	generateJWT = mockGenerateJWT

	testCases := []struct {
		name         string
		dbAdapter    dbadapter.DBInterface
		inputData    string
		expectedCode int
		expectedBody string
	}{
		{
			name:         "Success",
			dbAdapter:    &MockMongoClientSuccess{},
			inputData:    `{"username":"testuser", "password":"password123"}`,
			expectedCode: http.StatusOK,
			expectedBody: `{"token":"mocked.jwt.token"}`,
		},
		{
			name:         "InvalidDataProvided",
			dbAdapter:    &MockMongoClientSuccess{},
			inputData:    `{"username":"testuser", "password": 123}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorInvalidDataProvided),
		},
		{
			name:         "NoUsernameProvided",
			dbAdapter:    &MockMongoClientSuccess{},
			inputData:    `{"password": "123"}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorMissingUsername),
		},
		{
			name:         "NoPasswordProvided",
			dbAdapter:    &MockMongoClientSuccess{},
			inputData:    `{"username":"testuser"}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorMissingPassword),
		},
		{
			name:         "DBError",
			dbAdapter:    &MockMongoClientDBError{},
			inputData:    `{"username":"testuser", "password":"password123"}`,
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorRetrieveUserAccount),
		},
		{
			name:         "UserNotFound",
			dbAdapter:    &MockMongoClientEmptyDB{},
			inputData:    `{"username":"testuser", "password":"password123"}`,
			expectedCode: http.StatusUnauthorized,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorIncorrectCredentials),
		},
		{
			name:         "InvalidUserObtainedFromDB",
			dbAdapter:    &MockMongoClientInvalidUser{},
			inputData:    `{"username":"testuser", "password":"password123"}`,
			expectedCode: http.StatusInternalServerError,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorRetrieveUserAccount),
		},
		{
			name:         "IncorrectPassword",
			dbAdapter:    &MockMongoClientSuccess{},
			inputData:    `{"username":"testuser", "password":"a-password"}`,
			expectedCode: http.StatusUnauthorized,
			expectedBody: fmt.Sprintf(`{"error":"%s"}`, errorIncorrectCredentials),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbadapter.CommonDBClient = tc.dbAdapter
			req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(tc.inputData))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if tc.expectedCode != w.Code {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedCode, w.Code)
			}
			if w.Body.String() != tc.expectedBody {
				t.Errorf("Expected `%v`, got `%v`", tc.expectedBody, w.Body.String())
			}
		})
	}
}
