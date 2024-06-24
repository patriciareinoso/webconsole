// SPDX-License-Identifier: Apache-2.0

// +build ui

package webui_service

import (

    "github.com/gin-gonic/gin"
    "github.com/omec-project/webconsole/backend/logger"
    _ "github.com/omec-project/webconsole/docs"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func AddApiSwaggerService(engine *gin.Engine) {
	logger.WebUILog.Infoln("Adding API Swagger service")
	group := engine.Group("/docs")
	group.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}



