// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
//

// +build ui

 package configapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/webconsole/backend/logger"
)

var UI = true
 
func AddServiceUi(engine *gin.Engine) *gin.RouterGroup {
	group := engine.Group("/ui")
	logger.WebUILog.Infoln("Add UI service")

	group.StaticFS("/", http.Dir("/ui"))
 
	return group
 }

