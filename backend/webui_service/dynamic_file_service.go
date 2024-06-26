// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

// +build ui

package webui_service

import (
	"fmt"
    "io/ioutil"
    "errors"
    "os"

    "github.com/gin-gonic/gin"
    "github.com/omec-project/webconsole/backend/logger"
)

type route struct {
    Pattern string
	EnvVariable string
}

func AddDynamicFileService(engine *gin.Engine) {
	logger.WebUILog.Infoln("Adding Dynamic files service")
    group := engine.Group("/config/")
    for _, route := range routes {
        serveDynamicFile(group, route.Pattern, route.EnvVariable);
	}
}

func serveDynamicFile(group *gin.RouterGroup, pattern string, envVariable string){
    fileContent, err := readFileFromEnvVariable(envVariable)
	if err != nil {
        logger.WebUILog.Warningf("/config/%s route will not be served", pattern)
		return
	}
	group.GET(pattern, func(c *gin.Context) {
        c.String(200, "%s", fileContent)
    })
}

func readFileFromEnvVariable(envVariable string) ([]byte, error) {
	filePath := os.Getenv(envVariable)
    if filePath == "" {
		err := errors.New(fmt.Sprintf("Environment variable %s is not set", envVariable))
        logger.WebUILog.Warningln(err)
		return nil, err
    }

    fileContent, fileContentErr := ioutil.ReadFile(filePath)
    if fileContentErr != nil {
        logger.WebUILog.Warningf("Failed to read the file: %v", fileContentErr)
		return nil, fileContentErr
    }
	return fileContent, nil;
}

var routes = []route{
	{
        "/gnb",
		"GNB_CONFIG_PATH",
	},
	{
        "/upf",
		"UPF_CONFIG_PATH",
	},
}