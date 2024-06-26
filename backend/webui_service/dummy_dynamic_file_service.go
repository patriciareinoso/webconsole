// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

//go:build !ui

package webui_service

import (
	"github.com/gin-gonic/gin"
	"github.com/omec-project/webconsole/backend/logger"
)

func AddDynamicFileService(engine *gin.Engine) {
	logger.WebUILog.Infoln("Dynamic files service will not be added")
}
