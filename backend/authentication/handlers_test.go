// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package authentication

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/webconsole/dbadapter"
	"go.mongodb.org/mongo-driver/bson"
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

//func hashPassword(password string) string {
//	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
//	return string(hashed)
//}

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
		{"username": "janedoe", "password": "password123", "permissions": 1},
	}
	return rawUsers, nil
}

func (m *MockMongoClientSuccess) RestfulAPIGetOne(coll string, filter bson.M) (map[string]interface{}, error) {
	rawUser := map[string]interface{}{
		"username": "janedoe", "password": "password123", "permissions": 1,
	}
	return rawUser, nil
}

func (m *MockMongoClientSuccess) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
	rawUsers := []map[string]interface{}{
		{"username": "johndoe", "password": "password123", "permissions": 0},
		{"username": "janedoe", "password": "password123", "permissions": 1},
	}
	return rawUsers, nil
}

func (m *MockMongoClientSuccess) RestfulAPIPost(collName string, filter bson.M, postData map[string]interface{}) (bool, error) {
	return true, nil
}

func (m *MockMongoClientRegularUser) RestfulAPIGetOne(coll string, filter bson.M) (map[string]interface{}, error) {
	rawUser := map[string]interface{}{
		"username": "janedoe", "password": "password123", "permissions": 0,
	}
	return rawUser, nil
}

func (m *MockMongoClientRegularUser) RestfulAPIDeleteOne(collName string, filter bson.M) error {
	return nil
}

func TestGetUserAccounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	router.GET("/account", GetUserAccounts(mockJWTSecret))

	testCases := []struct {
		name         string
		dbAdapter    dbadapter.DBInterface
		expectedCode int
		expectedBody string
	}{
		{
			name:         "DBError",
			dbAdapter:    &MockMongoClientDBError{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: "error retrieving user accounts from DB",
		},
		{
			name:         "OneInvalidUser",
			dbAdapter:    &MockMongoClientInvalidUser{},
			expectedCode: http.StatusOK,
			expectedBody: `[{"username":"janedoe","permissions":1}]`,
		},
		{
			name:         "NoUsers",
			dbAdapter:    &MockMongoClientEmptyDB{},
			expectedCode: http.StatusOK,
			expectedBody: "[]",
		},
		{
			name:         "SuccessManyUsers",
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusOK,
			expectedBody: `[{"username":"johndoe","permissions":0},{"username":"janedoe","permissions":1}]`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbadapter.CommonDBClient = tc.dbAdapter
			req, _ := http.NewRequest(http.MethodGet, "/account", nil)
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
	router.GET("/account/:username", GetUserAccount(mockJWTSecret))

	testCases := []struct {
		name         string
		dbAdapter    dbadapter.DBInterface
		expectedCode int
		expectedBody string
	}{
		{
			name:         "Success",
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusOK,
			expectedBody: `{"username":"janedoe","permissions":1}`,
		},
		{
			name:         "DBError",
			dbAdapter:    &MockMongoClientDBError{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: `error retrieving user account from DB`,
		},
		{
			name:         "UserNotFound",
			dbAdapter:    &MockMongoClientEmptyDB{},
			expectedCode: http.StatusNotFound,
			expectedBody: `error: username not found`,
		},
		{
			name:         "InvalidUser",
			dbAdapter:    &MockMongoClientInvalidUser{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: `error unmarshalling user account`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbadapter.CommonDBClient = tc.dbAdapter
			req, _ := http.NewRequest(http.MethodGet, "/account/janedoe", nil)
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

func mockGeneratePassword() (string, error) {
	return "ValidPass123!", nil
}

func mockGeneratePasswordFailure() (string, error) {
	return "", errors.New("password generation failed")
}

func TestPostUserAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	router.POST("/account/:username", PostUserAccount(mockJWTSecret))

	testCases := []struct {
		name                 string
		dbAdapter            dbadapter.DBInterface
		generatePasswordMock func() (string, error)
		inputData            string
		expectedCode         int
		expectedBody         string
	}{
		{
			name:                 "CreateSecondUserWithoutPassword",
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            "{}",
			expectedCode:         http.StatusCreated,
			expectedBody:         `{"password":"ValidPass123!"}`,
		},
		{
			name:                 "CreateFirstUserWithoutPassword",
			dbAdapter:            &MockMongoClientEmptyDB{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            "{}",
			expectedCode:         http.StatusCreated,
			expectedBody:         `{"password":"ValidPass123!"}`,
		},
		{
			name:                 "CreateFirstUserWithPassword",
			dbAdapter:            &MockMongoClientEmptyDB{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"password" : "Admin1234"}`,
			expectedCode:         http.StatusCreated,
			expectedBody:         `{}`,
		},
		{
			name:                 "DBError",
			dbAdapter:            &MockMongoClientDBError{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"password" : "Admin1234"}`,
			expectedCode:         http.StatusInternalServerError,
			expectedBody:         "failed to retrieve users",
		},
		{
			name:                 "InvalidPassword",
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"password" : "1234"}`,
			expectedCode:         http.StatusBadRequest,
			expectedBody:         "Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.",
		},
		{
			name:                 "ErrorGeneratingPassword",
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePasswordFailure,
			inputData:            "{}",
			expectedCode:         http.StatusInternalServerError,
			expectedBody:         "failed to generate password",
		},
		{
			name:                 "InvalidJsonProvided",
			dbAdapter:            &MockMongoClientSuccess{},
			generatePasswordMock: mockGeneratePassword,
			inputData:            `{"password": 1234}`,
			expectedCode:         http.StatusBadRequest,
			expectedBody:         "invalid data provided",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			generatePasswordFunc = tc.generatePasswordMock
			dbadapter.CommonDBClient = tc.dbAdapter

			req, _ := http.NewRequest(http.MethodPost, "/account/adminadmin", strings.NewReader(tc.inputData))
			req.Header.Set("Content-Type", "application/json")
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

func TestDeleteUserAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	mockJWTSecret := []byte("mockSecret")
	router.DELETE("/account/:username", DeleteUserAccount(mockJWTSecret))

	testCases := []struct {
		name         string
		dbAdapter    dbadapter.DBInterface
		expectedCode int
		expectedBody string
	}{
		{
			name:         "DeleteRegularUser",
			dbAdapter:    &MockMongoClientRegularUser{},
			expectedCode: http.StatusOK,
			expectedBody: "{}",
		},
		{
			name:         "DeleteAdminUser",
			dbAdapter:    &MockMongoClientSuccess{},
			expectedCode: http.StatusBadRequest,
			expectedBody: "deleting an Admin account is not allowed.",
		},
		{
			name:         "InvalidUser",
			dbAdapter:    &MockMongoClientInvalidUser{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: "error unmarshalling user account",
		},
		{
			name:         "UserNotFound",
			dbAdapter:    &MockMongoClientEmptyDB{},
			expectedCode: http.StatusNotFound,
			expectedBody: "error: username not found",
		},
		{
			name:         "DBError",
			dbAdapter:    &MockMongoClientDBError{},
			expectedCode: http.StatusInternalServerError,
			expectedBody: "error retrieving user account",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbadapter.CommonDBClient = tc.dbAdapter
			req, _ := http.NewRequest(http.MethodDelete, "/account/janedoe", nil)
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
	router.POST("/account/:username/change_password", ChangeUserAccountPasssword(mockJWTSecret))

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
			inputData:    `{"password": "Admin1234"}`,
			expectedCode: http.StatusOK,
			expectedBody: "{}",
		},
		{
			name:         "DBError",
			dbAdapter:    &MockMongoClientDBError{},
			inputData:    `{"password": "Admin1234"}`,
			expectedCode: http.StatusInternalServerError,
			expectedBody: "failed to update user",
		},
		{
			name:         "InvalidPassword",
			dbAdapter:    nil,
			inputData:    `{"password": "1234"}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: "password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.",
		},
		{
			name:         "NoPasswordProvided",
			dbAdapter:    nil,
			inputData:    `{}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: "password is required",
		},
		{
			name:         "InvalidData",
			dbAdapter:    nil,
			inputData:    `{"password": 1234}`,
			expectedCode: http.StatusBadRequest,
			expectedBody: "invalid data provided",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbadapter.CommonDBClient = tc.dbAdapter
			req, _ := http.NewRequest(http.MethodPost, "/account/janedoe/change_password", strings.NewReader(tc.inputData))
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
