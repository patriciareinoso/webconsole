// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package authentication

import (
    "encoding/json"
    "errors"
	"reflect"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
    "github.com/omec-project/webconsole/configmodels"
    "github.com/omec-project/webconsole/dbadapter"
    "go.mongodb.org/mongo-driver/bson"
)

type MockMongoClientNoUsers struct {
    dbadapter.DBInterface
}

type MockMongoClientOneUser struct {
    dbadapter.DBInterface
}

type MockMongoClientManyUsers struct {
    dbadapter.DBInterface
}

type MockMongoClientManyUsersError struct {
    dbadapter.DBInterface
}

type MockMongoClientManyUsersInvalidUser struct {
    dbadapter.DBInterface
}

func (m *MockMongoClientNoUsers) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
    var results []map[string]interface{}
    return results, nil
}

func (m *MockMongoClientOneUser) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
	rawUsers := []map[string]interface{}{
        {"id": 1, "username": "janedoe", "password": "hidden", "permissions": 1},
    }
	return rawUsers, nil
}

func (m *MockMongoClientManyUsers) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
    rawUsers := []map[string]interface{}{
        {"id": 0, "username": "johndoe", "password": "secret", "permissions": 0},
        {"id": 1, "username": "janedoe", "password": "hidden", "permissions": 1},
    }
    return rawUsers, nil
}

func (m *MockMongoClientManyUsersError) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
    return nil, errors.New("DB error")
}

func (m *MockMongoClientManyUsersInvalidUser) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
    rawUsers := []map[string]interface{}{
        {"id": 0, "username": "johndoe", "password": 1234, "permissions": 0},
        {"id": 1, "username": "janedoe", "password": "hidden", "permissions": 1},
    }
    return rawUsers, nil
}

func TestGetUserAccounts_ManyUsers(t *testing.T) {
    expectedUsers := []*configmodels.User{
        {ID: 0, Username: "johndoe", Password: "", Permissions: 0},
        {ID: 1, Username: "janedoe", Password: "", Permissions: 1},
    }
	dbadapter.CommonDBClient = &MockMongoClientManyUsers{}
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    GetUserAccounts(c)

	if http.StatusOK != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusOK, w.Code)
    }
    var responseUsers []*configmodels.User
    err := json.Unmarshal(w.Body.Bytes(), &responseUsers)
	if err != nil {
        t.Errorf("Got error unmarshalling response %v", err)
    }
	if len(expectedUsers) != len(responseUsers){
        t.Fatalf("Expected %v users, got %v users", len(expectedUsers), len(responseUsers))
    }
    for i := range expectedUsers {
		if ! reflect.DeepEqual(expectedUsers[i], responseUsers[i]) {
			t.Errorf("Expected user %v, got user%v", expectedUsers[i], responseUsers[i])
		}
	}
}

func TestGetUserAccounts_NoUsers(t *testing.T) {
    expectedUsers := []*configmodels.User{}
	dbadapter.CommonDBClient = &MockMongoClientNoUsers{}
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    GetUserAccounts(c)

	if http.StatusOK != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusOK, w.Code)
    }
    var responseUsers []*configmodels.User
    err := json.Unmarshal(w.Body.Bytes(), &responseUsers)
	if err != nil {
        t.Errorf("Got error unmarshalling response %v", err)
    }
	if len(expectedUsers) != len(responseUsers){
        t.Fatalf("Expected %v users, got %v users", len(expectedUsers), len(responseUsers))
    }
    for i := range expectedUsers {
		if ! reflect.DeepEqual(expectedUsers[i], responseUsers[i]) {
			t.Errorf("Expected user %v, got user%v", expectedUsers[i], responseUsers[i])
		}
	}
}

func TestGetUserAccounts_DBError(t *testing.T) {
	dbadapter.CommonDBClient = &MockMongoClientManyUsersError{}
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    GetUserAccounts(c)

	if http.StatusInternalServerError != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusInternalServerError, w.Code)
    }
	expectedMessage := "error retrieving user accounts from DB"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestGetUserAccounts_InvalidUser(t *testing.T) {
	expectedUsers := []*configmodels.User{
        {ID: 1, Username: "janedoe", Password: "", Permissions: 1},
    }
	dbadapter.CommonDBClient = &MockMongoClientManyUsersInvalidUser{}
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    GetUserAccounts(c)

	if http.StatusOK != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusOK, w.Code)
    }
    var responseUsers []*configmodels.User
    err := json.Unmarshal(w.Body.Bytes(), &responseUsers)
	if err != nil {
        t.Errorf("Got error unmarshalling response %v", err)
    }
	if len(expectedUsers) != len(responseUsers){
        t.Fatalf("Expected %v users, got %v users", len(expectedUsers), len(responseUsers))
    }
    for i := range expectedUsers {
		if ! reflect.DeepEqual(expectedUsers[i], responseUsers[i]) {
			t.Errorf("Expected user %v, got user%v", expectedUsers[i], responseUsers[i])
		}
	}
}


/*
// TestGetUserAccounts_DBError tests the scenario where the DB client returns an error
func TestGetUserAccounts_DBError(t *testing.T) {
    // Mock the database client
    mockDBClient := new(MockDBClient)
    dbadapter.CommonDBClient = mockDBClient

    // Mock the logger
    logger.WebUILog = logger.MockLogger{}
    logger.DbLog = logger.MockLogger{}
    logger.AuthLog = logger.MockLogger{}

    // Simulate a DB error
    mockDBClient.On("RestfulAPIGetMany", userAccountDataColl, bson.M{}).Return(nil, errors.New("DB error"))

    // Create a test HTTP request and recorder
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    // Call the function
    GetUserAccounts(c)

    // Assert the status code
    assert.Equal(t, http.StatusInternalServerError, w.Code)

    // Assert the response body
    assert.Equal(t, "error retrieving user accounts from DB", w.Body.String())
}

// TestGetUserAccounts_UnmarshalError tests the scenario where unmarshalling of user data fails
func TestGetUserAccounts_UnmarshalError(t *testing.T) {
    // Mock the database client
    mockDBClient := new(MockDBClient)
    dbadapter.CommonDBClient = mockDBClient

    // Mock the logger
    logger.WebUILog = logger.MockLogger{}
    logger.DbLog = logger.MockLogger{}
    logger.AuthLog = logger.MockLogger{}

    // Sample invalid user data that will cause unmarshalling to fail
    rawUsers := []map[string]interface{}{
        {"username": "johndoe", "password": "secret"},
        {"username": "janedoe", "password": 1234}, // Invalid password type
    }

    // Expected unmarshalled user data (only the valid one)
    users := []*configmodels.User{
        {Username: "johndoe", Password: ""},
    }

    mockDBClient.On("RestfulAPIGetMany", userAccountDataColl, bson.M{}).Return(rawUsers, nil)

    // Create a test HTTP request and recorder
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    // Call the function
    GetUserAccounts(c)

    // Assert the status code
    assert.Equal(t, http.StatusOK, w.Code)

    // Assert the response body
    var responseUsers []*configmodels.User
    err := json.Unmarshal(w.Body.Bytes(), &responseUsers)
    assert.NoError(t, err)
    assert.Equal(t, users, responseUsers)
}
*/