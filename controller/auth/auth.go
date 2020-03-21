package auth

import (
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"xgit.xiaoniangao.cn/devops/ldap_server/api"
	"xgit.xiaoniangao.cn/devops/ldap_server/conf"
	"xgit.xiaoniangao.cn/devops/ldap_server/service/serviceauth"
	"xgit.xiaoniangao.cn/devops/ldap_server/util/net"
	"xgit.xiaoniangao.cn/xngo/lib/sdk/lib"
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
		conf.Logger.ErrorW("bind json for UserAuthReq fail",
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
