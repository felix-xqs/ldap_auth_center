package auth

import "github.com/gin-gonic/gin"

//InitRouter login
func InitRouter(app *gin.Engine) {
	feedsInfoGroup := app.Group("")
	feedsInfoGroup.POST("login", Login)
	feedsInfoGroup.POST("/v1/login/register", RegisterAndLogin)
	feedsInfoGroup.POST("/v1/user/auth", UserAuth)
	feedsInfoGroup.POST("/v1/password/verify", UserPwdVerify)
	feedsInfoGroup.GET("/v1/workwx/login", WXLogin)
	feedsInfoGroup.GET("/v1/workwx/attribute", GetWXAttribute)
}
