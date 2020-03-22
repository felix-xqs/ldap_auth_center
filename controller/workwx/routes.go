package workwx

import "github.com/gin-gonic/gin"

//InitRouter login
func InitRouter(app *gin.Engine) {
	feedsInfoGroup := app.Group("")
	feedsInfoGroup.POST("/v1/workwx/token", GetWXToken)
	feedsInfoGroup.GET("/v1/workwx/callback", GetWXEcho)
	feedsInfoGroup.POST("/v1/workwx/callback", GetWXInfo)
	feedsInfoGroup.POST("/v1/workwx/update", UpdateLdapInfo)

}
