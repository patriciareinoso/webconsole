// SPDX-FileCopyrightText: 2024 Open Networking Foundation <info@opennetworking.org>
// Copyright 2024 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package configapi

import (
	"github.com/gin-gonic/gin"
	"github.com/omec-project/webconsole/backend/factory"
	"github.com/omec-project/webconsole/backend/logger"
)

func AddServiceUi(engine *gin.Engine) *gin.RouterGroup {
	group := engine.Group("/ui")

	logger.WebUILog.Infoln("AddServiceUi")
	routeName := factory.WebUIConfig.Configuration.Ui.RouteName
	path := factory.WebUIConfig.Configuration.Ui.Path

	if routeName != "" && path != "" {
		logger.WebUILog.Infoln("Add UI service")
		group.Static(routeName, path)
	} else {
		logger.WebUILog.Infoln("UI service is not created")
	}

	return group
}
