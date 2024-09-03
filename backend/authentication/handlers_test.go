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
    "strings"

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

type MockMongoClientDBError struct {
    dbadapter.DBInterface
}

type MockMongoClientInvalidUser struct {
    dbadapter.DBInterface
}

type MockMongoClientOneUserNoUser struct {
    dbadapter.DBInterface
}

type MockMongoClientAdminUser struct {
    dbadapter.DBInterface
}

type MockMongoClientRegularUser struct {
    dbadapter.DBInterface
}


func (m *MockMongoClientNoUsers) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
    var results []map[string]interface{}
    return results, nil
}

func (m *MockMongoClientNoUsers)RestfulAPIPost(collName string, filter bson.M, postData map[string]interface{}) (bool, error){
    return true, nil
}

func (m *MockMongoClientManyUsers) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
    rawUsers := []map[string]interface{}{
        {"id": 0, "username": "johndoe", "password": "secret", "permissions": 0},
        {"id": 1, "username": "janedoe", "password": "hidden", "permissions": 1},
    }
    return rawUsers, nil
}

func (m *MockMongoClientRegularUser) RestfulAPIGetOne(coll string, filter bson.M) (map[string]interface{}, error) {
	rawUser := map[string]interface{}{
        "id": 5, "username": "janedoe", "password": "hidden", "permissions": 0,
    }
	return rawUser, nil
}

func (m *MockMongoClientRegularUser) RestfulAPIDeleteOne(collName string, filter bson.M) error{
	return nil
}


func (m *MockMongoClientAdminUser) RestfulAPIGetOne(coll string, filter bson.M) (map[string]interface{}, error) {
	rawUser := map[string]interface{}{
        "id": 5, "username": "janedoe", "password": "hidden", "permissions": 1,
    }
	return rawUser, nil
}

func (m *MockMongoClientManyUsers) RestfulAPIGetOne(coll string, filter bson.M) (map[string]interface{}, error) {
	rawUser := map[string]interface{}{
        "id": 5, "username": "janedoe", "password": "hidden", "permissions": 1,
    }
	return rawUser, nil
}

func (m *MockMongoClientManyUsers)RestfulAPIPost(collName string, filter bson.M, postData map[string]interface{}) (bool, error){
    return true, nil
}

func (m *MockMongoClientDBError) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
    return nil, errors.New("DB error")
}

func (m *MockMongoClientDBError) RestfulAPIGetOne(coll string, filter bson.M) (map[string]interface{}, error) {
    return nil, errors.New("DB error")
}

func (m *MockMongoClientDBError)RestfulAPIPost(collName string, filter bson.M, postData map[string]interface{}) (bool, error){
    return false, errors.New("DB error")
}

func (m *MockMongoClientInvalidUser) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]interface{}, error) {
    rawUsers := []map[string]interface{}{
        {"id": 0, "username": "johndoe", "password": 1234, "permissions": 0},
        {"id": 1, "username": "janedoe", "password": "hidden", "permissions": 1},
    }
    return rawUsers, nil
}

func (m *MockMongoClientInvalidUser) RestfulAPIGetOne(collName string, filter bson.M) (map[string]interface{}, error){
    rawUser := map[string]interface{}{
        "id": 0, 
        "username": "johndoe", 
        "password": 1234, 
        "permissions": 0,
    }
    return rawUser, nil
}

func (m *MockMongoClientOneUserNoUser) RestfulAPIGetOne(collName string, filter bson.M) (map[string]interface{}, error){
    return map[string]interface{}{}, nil
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
	dbadapter.CommonDBClient = &MockMongoClientDBError{}
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
	dbadapter.CommonDBClient = &MockMongoClientInvalidUser{}
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

func TestGetUserAccount_Successful(t *testing.T) {
    expectedUser := configmodels.User{
        ID: 5, 
        Username: "janedoe", 
        Password: "", 
        Permissions: 1,
    }
	dbadapter.CommonDBClient = &MockMongoClientManyUsers{}
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    GetUserAccount(c)

	if http.StatusOK != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusOK, w.Code)
    }
    var responseUser configmodels.User
    err := json.Unmarshal(w.Body.Bytes(), &responseUser)
	if err != nil {
        t.Errorf("Got error unmarshalling response %v", err)
    }
    if ! reflect.DeepEqual(expectedUser, responseUser) {
        t.Errorf("Expected user %v, got user%v", expectedUser, responseUser)
	}
}

func TestGetUserAccount_DBError(t *testing.T) {

	dbadapter.CommonDBClient = &MockMongoClientDBError{}
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    GetUserAccount(c)

	if http.StatusInternalServerError != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusInternalServerError, w.Code)
    }
    expectedMessage := "error retrieving user account from DB"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestGetUserAccount_UserNotFound(t *testing.T) {

	dbadapter.CommonDBClient = &MockMongoClientOneUserNoUser{}
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    GetUserAccount(c)

	if http.StatusNotFound != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusNotFound, w.Code)
    }
    expectedMessage := "error: user ID not found"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestGetUserAccount_InvalidUser(t *testing.T) {

	dbadapter.CommonDBClient = &MockMongoClientInvalidUser{}
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)

    GetUserAccount(c)

	if http.StatusInternalServerError != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusInternalServerError, w.Code)
    }
    expectedMessage := "error unmarshalling user account"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestPostUserAccount_InvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    //adminUser := `{"username": "testadmin", "password": "Admin123"}`
    adminUser := `{"username": "testadmin", "password": 1234}`
    
	c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON

	PostUserAccount(c)

    if http.StatusBadRequest != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusBadRequest, w.Code)
    }
    expectedMessage := "invalid data provided"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestPostUserAccount_InvalidJSON2(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    
	c.Request = httptest.NewRequest(http.MethodPost, "/account", nil) // Invalid JSON

	PostUserAccount(c)

    if http.StatusBadRequest != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusBadRequest, w.Code)
    }
    expectedMessage := "invalid data provided"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestPostUserAccount_InvalidDataNoUsername(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    adminUser := `{"password": "Admin1234"}`
    
	c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON

	PostUserAccount(c)

    if http.StatusBadRequest != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusBadRequest, w.Code)
    }
    expectedMessage := "username is required"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}


func mockGeneratePassword() (string, error) {
	return "ValidPass123!", nil
}

func mockGeneratePasswordFailure() (string, error) {
	return "", errors.New("password generation failed")
}

func mockValidatePassword(password string) bool {
	return len(password) >= 8 // Simplified validation for this example
}

func TestPostUserAccount_ErrorGeneratingPassword(t *testing.T) {
    generatePasswordFunc = mockGeneratePasswordFailure
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    adminUser := `{"username": "adminadmin"}`
    
	c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON

	PostUserAccount(c)

    if http.StatusInternalServerError != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusInternalServerError, w.Code)
    }
    expectedMessage := "failed to generate password"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestPostUserAccount_ErrorValidatePassword(t *testing.T) {
    //generatePasswordFunc = mockGeneratePasswordFailure
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    adminUser := `{"username": "adminadmin", "password" : "1234"}`
    
	c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON

	PostUserAccount(c)

    if http.StatusBadRequest != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusBadRequest, w.Code)
    }
    expectedMessage := "Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol."
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestPostUserAccount_FailedToRetriveUsers(t *testing.T) {
    //generatePasswordFunc = mockGeneratePasswordFailure
    dbadapter.CommonDBClient = &MockMongoClientDBError{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    adminUser := `{"username": "adminadmin", "password" : "Admin1234"}`
    
	c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON

	PostUserAccount(c)

    if http.StatusInternalServerError != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusInternalServerError, w.Code)
    }
    expectedMessage := "failed to retrieve users"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}


func TestPostUserAccount_FirstUserIsCreated(t *testing.T) {
    //generatePasswordFunc = mockGeneratePasswordFailure
    dbadapter.CommonDBClient = &MockMongoClientNoUsers{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    adminUser := `{"username": "adminadmin", "password" : "Admin1234"}`
    
	c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON

	PostUserAccount(c)

    if http.StatusCreated != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusCreated, w.Code)
    }
    expectedMessage := `{"id":0}`
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestPostUserAccount_FirstUserIsCreatedPasswordGenerated(t *testing.T) {
    generatePasswordFunc = mockGeneratePassword
    dbadapter.CommonDBClient = &MockMongoClientNoUsers{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    adminUser := `{"username": "adminadmin"}`
    
	c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON

	PostUserAccount(c)

    if http.StatusCreated != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusCreated, w.Code)
    }
    expectedMessage := `{"id":0,"password":"ValidPass123!"}`
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestPostUserAccount_SecondUserIsCreated(t *testing.T) {
    generatePasswordFunc = mockGeneratePassword
    dbadapter.CommonDBClient = &MockMongoClientManyUsers{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    adminUser := `{"username": "adminadmin"}`
    
	c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON

	PostUserAccount(c)

    if http.StatusCreated != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusCreated, w.Code)
    }
    expectedMessage := `{"id":0,"password":"ValidPass123!"}`
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestDeleteUserAccount_DBError(t *testing.T) {

    dbadapter.CommonDBClient = &MockMongoClientDBError{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    
	//c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON
    c.Params = gin.Params{gin.Param{Key: "id", Value: "testuser"}}

	DeleteUserAccount(c)

    if http.StatusInternalServerError != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusInternalServerError, w.Code)
    }
    expectedMessage := "error retrieving user account"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestDeleteUserAccount_UserNotFound(t *testing.T) {

    dbadapter.CommonDBClient = &MockMongoClientOneUserNoUser{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    
	//c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON
    c.Params = gin.Params{gin.Param{Key: "id", Value: "testuser"}}

	DeleteUserAccount(c)

    if http.StatusNotFound != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusNotFound, w.Code)
    }
    expectedMessage := "error: user ID not found"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestDeleteUserAccount_InvalidUser(t *testing.T) {

    dbadapter.CommonDBClient = &MockMongoClientInvalidUser{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    
	//c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON
    c.Params = gin.Params{gin.Param{Key: "id", Value: "testuser"}}

	DeleteUserAccount(c)

    if http.StatusInternalServerError != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusInternalServerError, w.Code)
    }
    expectedMessage := "error unmarshalling user account"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestDeleteUserAccount_DeleteAdmin(t *testing.T) {

    dbadapter.CommonDBClient = &MockMongoClientAdminUser{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    
	//c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON
    c.Params = gin.Params{gin.Param{Key: "id", Value: "testuser"}}

	DeleteUserAccount(c)

    if http.StatusBadRequest != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusBadRequest, w.Code)
    }
    expectedMessage := "deleting an Admin account is not allowed."
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

func TestDeleteUserAccount_DeleteRegularUser(t *testing.T) {

    dbadapter.CommonDBClient = &MockMongoClientRegularUser{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
    
	//c.Request = httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(adminUser)) // Invalid JSON
    c.Params = gin.Params{gin.Param{Key: "id", Value: "testuser"}}

	DeleteUserAccount(c)

    if http.StatusOK != w.Code {
        t.Errorf("Expected %v, got %v", http.StatusOK, w.Code)
    }
    expectedMessage := "{}"
	if  w.Body.String() != expectedMessage{
		t.Errorf("Expected %v, got %v", expectedMessage, w.Body.String())
	}
}

