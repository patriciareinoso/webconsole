// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
//

/*
 * Connectivity Service Configuration
 *
 * APIs to configure connectivity service in Aether Network
 *
 * API version: 1.0.0
 *
 */

 package configapi

 import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/webconsole/backend/logger"
 )
 
 func AddServiceUi(engine *gin.Engine) *gin.RouterGroup {
	group := engine.Group("/")
	logger.WebUILog.Infoln("Add UI service")
	group.StaticFS("/", http.Dir("/ui"))
 
	return group
 }
 

 