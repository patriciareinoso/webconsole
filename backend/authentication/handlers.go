// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package authentication

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/omec-project/webconsole/backend/logger"
	"github.com/omec-project/webconsole/configmodels"
	"github.com/omec-project/webconsole/dbadapter"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

const userAccountDataColl = "webconsoleData.snapshots.userAccountData"

var (
	generatePasswordFunc = generatePassword
	validatePasswordFunc = validatePassword
	generateJWTFunc      = generateJWT
)

func mapToByte(data map[string]interface{}) (ret []byte) {
	ret, _ = json.Marshal(data)
	return
}
func toBsonM(data interface{}) (ret bson.M) {
	tmp, err := json.Marshal(data)
	if err != nil {
		logger.DbLog.Errorln("Could not marshall data")
		return nil
	}
	err = json.Unmarshal(tmp, &ret)
	if err != nil {
		logger.DbLog.Errorln("Could not unmarshall data")
		return nil
	}
	return ret
}

func GetUserAccounts(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		users, err := FetchUserAccounts()
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, users)
	}
}

func FetchUserAccounts() ([]*configmodels.User, error) {
	rawUsers, errGetMany := dbadapter.CommonDBClient.RestfulAPIGetMany(userAccountDataColl, bson.M{})
	if errGetMany != nil {
		logger.DbLog.Errorln(errGetMany)
		return nil, fmt.Errorf("error retrieving user accounts from DB")
	}
	var users []*configmodels.User
	users = make([]*configmodels.User, 0)
	for _, rawUser := range rawUsers {
		var userData configmodels.User
		err := json.Unmarshal(mapToByte(rawUser), &userData)
		if err != nil {
			logger.AuthLog.Errorf("could not unmarshall user account")
			continue
		}
		userData.Password = ""
		users = append(users, &userData)
	}
	return users, nil
}

func IsFirstAccountIssued() (bool, error) {
	users, err := FetchUserAccounts()
	if err != nil {
		return false, err
	}
	return len(users) > 0, nil
}

func GetUserAccount(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.WebUILog.Infoln("get user account")
		var err error
		username := c.Param("username")
		filter := bson.M{"username": username}
		rawUser, err := dbadapter.CommonDBClient.RestfulAPIGetOne(userAccountDataColl, filter)
		if err != nil {
			logger.DbLog.Errorln(err)
			c.String(http.StatusInternalServerError, "error retrieving user account from DB")
			return
		}
		if len(rawUser) == 0 {
			c.String(http.StatusNotFound, "error: username not found")
			return
		}
		var userAccount configmodels.User
		err = json.Unmarshal(mapToByte(rawUser), &userAccount)
		if err != nil {
			logger.AuthLog.Errorln(err)
			c.String(http.StatusInternalServerError, "error unmarshalling user account")
			return
		}
		userAccount.Password = ""
		c.JSON(http.StatusOK, userAccount)
	}
}

func PostUserAccount(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.WebUILog.Infoln("create user account")
		var user configmodels.User
		err := c.ShouldBindJSON(&user)
		if err != nil {
			logger.AuthLog.Errorln(err.Error())
			c.String(http.StatusBadRequest, "invalid data provided")
			return
		}
		if user.Username == "" {
			c.String(http.StatusBadRequest, "username is required")
			return
		}
		var shouldGeneratePassword = user.Password == ""
		if shouldGeneratePassword {
			generatedPassword, err := generatePasswordFunc()
			if err != nil {
				logger.AuthLog.Errorln(err.Error())
				c.String(http.StatusInternalServerError, "failed to generate password")
				return
			}
			user.Password = generatedPassword
		}

		if !validatePasswordFunc(user.Password) {
			errorMessage := "Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol."
			logger.AuthLog.Errorln("invalid password provided")
			c.String(http.StatusBadRequest, errorMessage)
			return
		}

		rawUsers, err := dbadapter.CommonDBClient.RestfulAPIGetMany(userAccountDataColl, bson.M{})
		if err != nil {
			logger.DbLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "failed to retrieve user accounts")
			return
		}
		user.Permissions = 0
		if len(rawUsers) == 0 {
			logger.DbLog.Errorln(len(rawUsers))
			user.Permissions = 1 //if this is the first user it will be admin
		}
		password := user.Password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			logger.AuthLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "failed to create user")
			return
		}
		user.Password = string(hashedPassword)
		userBsonA := toBsonM(user)
		filter := bson.M{"username": user.Username}
		_, err = dbadapter.CommonDBClient.RestfulAPIPost(userAccountDataColl, filter, userBsonA)
		if err != nil {
			//if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			//    logErrorAndWriteResponse("user with given username already exists", http.StatusBadRequest, w)
			//    return
			//}
			logger.DbLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "failed to create user")
			return
		}
		if shouldGeneratePassword {
			c.JSON(http.StatusCreated, gin.H{"password": password})
			return
		}
		c.JSON(http.StatusCreated, gin.H{})
	}
}

func DeleteUserAccount(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.WebUILog.Infoln("delete user account")
		username := c.Param("username")
		filter := bson.M{"username": username}
		rawUser, err := dbadapter.CommonDBClient.RestfulAPIGetOne(userAccountDataColl, filter)
		if err != nil {
			logger.DbLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "error retrieving user account")
			return
		}
		if len(rawUser) == 0 {
			c.String(http.StatusNotFound, "error: username not found")
			return
		}
		var userAccount configmodels.User
		err = json.Unmarshal(mapToByte(rawUser), &userAccount)
		if err != nil {
			logger.AuthLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "error unmarshalling user account")
			return
		}
		if userAccount.Permissions == 1 {
			errMessage := "deleting an Admin account is not allowed."
			logger.AuthLog.Errorln(errMessage)
			c.String(http.StatusBadRequest, errMessage)
			return
		}
		errDelOne := dbadapter.CommonDBClient.RestfulAPIDeleteOne(userAccountDataColl, filter)
		if errDelOne != nil {
			logger.DbLog.Errorln(errDelOne)
			c.String(http.StatusInternalServerError, "error deleting user account")
			return
		}
		c.JSON(http.StatusOK, gin.H{})
	}
}
func ChangeUserAccountPasssword(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.WebUILog.Infoln("change user password")
		username := c.Param("username")
		var userAccount configmodels.User
		err := c.ShouldBindJSON(&userAccount)
		if err != nil {
			logger.AuthLog.Errorln(err.Error())
			c.String(http.StatusBadRequest, "invalid data provided")
			return
		}
		if userAccount.Password == "" {
			c.String(http.StatusBadRequest, "password is required")
			return
		}
		if !validatePasswordFunc(userAccount.Password) {
			errorMessage := "password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol."
			c.String(http.StatusBadRequest, errorMessage)
			return
		}
		// CHECK IF USER EXISTS
		userAccount.Username = username
		password := userAccount.Password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			logger.AuthLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "failed to create user")
			return
		}
		userAccount.Password = string(hashedPassword)
		userBsonA := toBsonM(userAccount)

		filter := bson.M{"username": username}
		_, err = dbadapter.CommonDBClient.RestfulAPIPost(userAccountDataColl, filter, userBsonA)
		if err != nil {
			logger.DbLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "failed to update user")
			return
		}
		c.JSON(http.StatusOK, gin.H{})
	}
}
func Login(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		var userRequest configmodels.User
		err := c.ShouldBindJSON(&userRequest)
		if err != nil {
			logger.AuthLog.Errorln(err.Error())
			c.String(http.StatusBadRequest, "invalid data provided")
			return
		}
		if userRequest.Username == "" {
			c.String(http.StatusBadRequest, "username is required")
			return
		}
		if userRequest.Password == "" {
			c.String(http.StatusBadRequest, "password is required")
			return
		}

		filter := bson.M{"username": userRequest.Username}
		rawUser, err := dbadapter.CommonDBClient.RestfulAPIGetOne(userAccountDataColl, filter)
		if err != nil {
			logger.DbLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "error retrieving user account")
			return
		}
		if len(rawUser) == 0 {
			c.String(http.StatusUnauthorized, "the username or password is incorrect. Try again.")
			return
		}
		var userAccount configmodels.User
		err = json.Unmarshal(mapToByte(rawUser), &userAccount)
		if err != nil {
			logger.AuthLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "error unmarshalling user account")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(userAccount.Password), []byte(userRequest.Password)); err != nil {
			c.String(http.StatusUnauthorized, "the username or password is incorrect. Try again.")
			return
		}
		jwt, err := generateJWTFunc(userAccount.Username, userAccount.Permissions, jwtSecret)
		if err != nil {
			logger.AuthLog.Errorln(err.Error())
			c.String(http.StatusInternalServerError, "error generating token")
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": jwt})
	}
}

// Generates a random 16 chars long password that contains uppercase and lowercase characters and numbers or symbols.
func generatePassword() (string, error) {
	const (
		uppercaseSet         = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowercaseSet         = "abcdefghijklmnopqrstuvwxyz"
		numbersAndSymbolsSet = "0123456789*?@"
		allCharsSet          = uppercaseSet + lowercaseSet + numbersAndSymbolsSet
	)
	uppercase, err := getRandomChars(uppercaseSet, 2)
	if err != nil {
		return "", err
	}
	lowercase, err := getRandomChars(lowercaseSet, 2)
	if err != nil {
		return "", err
	}
	numbersOrSymbols, err := getRandomChars(numbersAndSymbolsSet, 2)
	if err != nil {
		return "", err
	}
	allChars, err := getRandomChars(allCharsSet, 10)
	if err != nil {
		return "", err
	}
	res := []rune(uppercase + lowercase + numbersOrSymbols + allChars)
	mrand.Shuffle(len(res), func(i, j int) {
		res[i], res[j] = res[j], res[i]
	})
	return string(res), nil
}

func getRandomChars(charset string, length int) (string, error) {
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}

func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	hasCapital := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasCapital {
		return false
	}
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		return false
	}
	hasNumberOrSymbol := regexp.MustCompile(`[0-9!@#$%^&*()_+\-=\[\]{};':"|,.<>?~]`).MatchString(password)

	return hasNumberOrSymbol
}

func GenerateJWTSecret() ([]byte, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return bytes, fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	return bytes, nil
}

// Helper function to generate a JWT
func generateJWT(username string, permissions int, jwtSecret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtGocertClaims{
		Username:    username,
		Permissions: permissions,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
