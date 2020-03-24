package auth

import (
	"github.com/felix-xqs/ldap_auth_center/api"
	"github.com/felix-xqs/ldap_auth_center/conf"
	"github.com/felix-xqs/ldap_auth_center/util/net"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
)

// UserAuth ...
func UserAuth(ctx *gin.Context) {
	req := &api.UserAuthReq{}
	traceID := ctx.GetString("traceID")
	if traceID == "" {
		traceID = uuid.NewV4().String()
	}
	var err error
	if err = ctx.ShouldBindJSON(req); err != nil {
		conf.C.Log.ErrorW("bind json for UserAuthReq fail",
			map[string]interface{}{"err": err, "traceID": traceID})
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}
	resp, err := serviceauth.UserAuth(req.LoginName, traceID)
	if err != nil {
		conf.Logger.ErrorW("UserAuth ", map[string]interface{}{"error": err, "loginName": req.LoginName, "traceID": traceID})
		net.Reply200(ctx, resp)
		return
	}

	net.Reply200(ctx, resp)
}

// UserPwdVerify ...
func UserPwdVerify(ctx *gin.Context) {
	req := &api.UserPwdVerifyReq{}
	traceID := ctx.GetString("traceID")
	if traceID == "" {
		traceID = uuid.NewV4().String()
	}
	var err error
	if err = ctx.ShouldBindJSON(req); err != nil {
		conf.Logger.ErrorW("bind json for UserAuthReq fail",
			map[string]interface{}{"err": err, "traceID": traceID})
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}
	resp, err := serviceauth.VerifyPwd(req.Password, traceID)
	if err != nil {
		conf.Logger.ErrorW("verify password failed", map[string]interface{}{"error": err, "traceID": traceID})
		net.Reply200(ctx, resp)
		return
	}
	net.Reply200(ctx, resp)
}
