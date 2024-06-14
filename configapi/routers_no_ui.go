// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
//

//go:build !ui
// +build !ui

package configapi

import (
	"github.com/gin-gonic/gin"
	"github.com/omec-project/webconsole/backend/logger"
)

func AddServiceUi(engine *gin.Engine) *gin.RouterGroup {
	logger.WebUILog.Infoln("UI service will not be added")
	return nil
}
