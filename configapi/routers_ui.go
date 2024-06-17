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
	"io/fs"
	"embed"
	//"webconsole/ui"
)

//go:embed all:dist
var FrontendFS embed.FS

func newFrontendFileServer() http.Handler {
	frontendFS, err := fs.Sub(FrontendFS, "dist")
	if err != nil {
		logger.WebUILog.Fatal(err)
	}
	return http.FileServer(http.FS(frontendFS))
}
 
func AddServiceUi(engine *gin.Engine) *gin.RouterGroup {
	group := engine.Group("/")
	logger.WebUILog.Infoln("Add UI service")

	//group.StaticFS("/", http.Dir("ui"))
 
	//frontendHandler := newFrontendFileServer()
	//router := http.NewServeMux()
	//router.Handle("/", frontendHandler)
	//return nil


	//router := gin.Default()
	dist, err := fs.Sub(FrontendFS, "dist")
	if err != nil {
		logger.WebUILog.Fatal(err)
		return nil
	}
   
	group.StaticFS("/", http.FS(dist))
	//router.Run()
	return group
 }

