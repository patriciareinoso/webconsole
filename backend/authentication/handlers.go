// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package authentication

import (
    //"errors"
    //"fmt"
    "encoding/json"
    "crypto/rand"
    //"strings"
    "net/http"
	mrand "math/rand"
    "math/big"
    "github.com/gin-gonic/gin"
    //"github.com/omec-project/util/httpwrapper"
    "github.com/omec-project/webconsole/backend/logger"
    "github.com/omec-project/webconsole/configmodels"
    "github.com/omec-project/webconsole/dbadapter"
    "go.mongodb.org/mongo-driver/bson"
    "regexp"
)

const userAccountDataColl = "webconsoleData.snapshots.userAccountData"

var (
    generatePasswordFunc = generatePassword
    validatePasswordFunc = validatePassword
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

func GetUserAccounts(c *gin.Context) {
    logger.WebUILog.Infoln("get all user accounts")
    rawUsers, errGetMany := dbadapter.CommonDBClient.RestfulAPIGetMany(userAccountDataColl, bson.M{})
    if errGetMany != nil {
        logger.DbLog.Errorln(errGetMany)
        c.String(http.StatusInternalServerError, "error retrieving user accounts from DB")
        return
    }
    var users []*configmodels.User
    users = make([]*configmodels.User, 0)
    for _, rawUser := range rawUsers {
        var userData configmodels.User
        err := json.Unmarshal(mapToByte(rawUser), &userData)
        if err != nil {
            logger.AuthLog.Errorf("Could not unmarshall user")
            continue
        }
        userData.Password = ""
        users = append(users, &userData)
    }
    c.JSON(http.StatusOK, users)
}

func GetUserAccount(c *gin.Context) {
    logger.WebUILog.Infoln("get user account")

    var err error
    username := c.Param("username")
    /*
    if id == "me" {
        claims, headerErr := getClaimsFromAuthorizationHeader(c.Header.Get("Authorization"), env.JWTSecret)
        if headerErr != nil {
            logger.DbLog.Errorln(err)
            c.JSON(http.StatusUnauthorized, gin.H{"error": headerErr.Error()})
            return
        }
        filter := bson.M{"username": claims.Username}
    } else {
        filter := bson.M{"id": id}
    }*/
    filter := bson.M{"username": username}
    rawUser, err := dbadapter.CommonDBClient.RestfulAPIGetOne(userAccountDataColl, filter)
    logger.DbLog.Errorln(rawUser)
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

func PostUserAccount(c *gin.Context) {
    logger.WebUILog.Infoln("create user account")
    var user configmodels.User
    err := c.ShouldBindJSON(&user)

    if err != nil {
        logger.AuthLog.Errorln(err)
        c.String(http.StatusBadRequest, "invalid data provided")
        return
    }
    var shouldGeneratePassword = user.Password == ""
    if shouldGeneratePassword {
        generatedPassword, err := generatePasswordFunc()
        if err != nil {
            errorMessage := "failed to generate password"
            logger.AuthLog.Errorln(errorMessage)
            c.String(http.StatusInternalServerError, errorMessage)
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
        c.String(http.StatusInternalServerError, "failed to retrieve users")
        return
    }
    logger.DbLog.Errorln(rawUsers)
    
    user.Permissions = 0
    if len(rawUsers) == 0 {
        logger.DbLog.Errorln(len(rawUsers))
        user.Permissions = 1 //if this is the first user it will be admin
    }

    username := c.Param("username")
    user.Username = username
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
        c.JSON(http.StatusCreated, gin.H{"password": user.Password})
        return
    }
    c.JSON(http.StatusCreated, gin.H{})
}

func DeleteUserAccount(c *gin.Context) {
    logger.WebUILog.Infoln("delete user account")

    username := c.Param("username")
    filter := bson.M{"username": username}
    rawUser, err := dbadapter.CommonDBClient.RestfulAPIGetOne(userAccountDataColl, filter)
    if err != nil {
        logger.DbLog.Errorln(err)
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
        logger.AuthLog.Errorln(err)
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
        c.String(http.StatusInternalServerError,  "error deleting user account")
        return
	}
    c.JSON(http.StatusOK, gin.H{})
}

func ChangeUserAccountPasssword(c *gin.Context) {
    logger.WebUILog.Infoln("change user password")
    username := c.Param("username")
    //if id == "me" {
    //    claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
    //    if err != nil {
    //        logger.DbLog.Errorln(err)
    //        c.JSON(http.StatusUnauthorized, gin.H{"error": headerErr.Error()})
    //    }
    //    userAccount, err := env.DB.RetrieveUserByUsername(claims.Username)
    //    if err != nil {
    //        logger.DbLog.Errorln(err)
    //        c.JSON(http.StatusUnauthorized, gin.H{"error": headerErr.Error()})
    //    }
    //    id = strconv.Itoa(userAccount.ID)
    //}
    var userAccount configmodels.User
    err := c.ShouldBindJSON(&userAccount)
    if err != nil {
        logger.AuthLog.Errorln(err)
        c.String(http.StatusBadRequest, "invalid data provided")
        return
    }
    if userAccount.Password == "" {
        c.String(http.StatusBadRequest, "password is required")
        return
    }
    if !validatePasswordFunc(userAccount.Password) {
        errorMessage:= "password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol."
        c.String(http.StatusBadRequest, errorMessage)
        return
    }

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

func Login(c *gin.Context) {
    logger.WebUILog.Infoln("log in")

    c.JSON(http.StatusOK, nil)
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



