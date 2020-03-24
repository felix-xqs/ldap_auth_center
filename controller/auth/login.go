package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/satori/go.uuid"
	"net/http"
	"strconv"
)

//Login login create token
func Login(ctx *gin.Context) {
	req := &ldapapi.LoginReq{}
	traceID := ctx.GetString("traceID")
	if traceID == "" {
		traceID = uuid.NewV4().String()
	}
	var err error
	if err = ctx.ShouldBindJSON(req); err != nil {
		conf.Logger.ErrorW("bind json for LoginReq fail",
			map[string]interface{}{"err": err, "traceId": traceID})
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}

	resp, err := serviceauth.UserAuth(req.LoginName, traceID)
	if err != nil {
		conf.Logger.ErrorW("UserAuth ", map[string]interface{}{"error": err, "loginName": req.LoginName, "traceID": traceID})
		net.Reply200(ctx, resp)
		return
	}

	token, uid, err := serviceauth.Login(req.LoginName, req.LoginPwd)
	if err != nil {
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}

	userInfo, err := serviceldap.GetUserInfoByUID(uid, []string{})
	ctx.SetCookie(conf.CookieTicketKey, token, conf.CookieDefaultMaxAge, "",
		conf.C.LdapConfig.BaseDomain, false, false)
	URL := conf.C.DefaultRedirectURL
	if req.ReturnURL != "" {
		URL = req.ReturnURL
	}
	userInfo["url"] = URL
	userInfo["admin"] = "0"
	if req.LoginName == conf.C.ServerConfig.UserName {
		userInfo["admin"] = "1"
		userInfo["url"] = conf.C.DefaultRedirectURL
	}

	net.Reply200(ctx, net.OkWithData(userInfo))
}

//WXLogin  微信扫码登录
func WXLogin(ctx *gin.Context) {
	req := &api.WorkWXScanReq{}
	traceID := ctx.GetString("traceID")
	if traceID == "" {
		traceID = uuid.NewV4().String()
	}
	var err error
	if err := ctx.ShouldBindQuery(req); err != nil {
		conf.Logger.ErrorW("bind query for WorkWXScanReq fail",
			map[string]interface{}{"err": err, "traceId": traceID})
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}
	if req.RedirectURL == "" {
		req.RedirectURL = conf.C.DefaultRedirectURL
	}
	if req.State != servicewx.State {
		conf.Logger.ErrorW("WorkWXLoginReq illegal", map[string]interface{}{"traceId": traceID})
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, "WorkWXLoginReq illegal,state is incorrect"))
		return
	}

	userID, err := servicewx.GetUserIDByCode(req.Code, traceID)

	if err != nil {
		net.Reply200(ctx, net.FailWithDetail(lib.CodeSignCheck, err.Error()))
		return
	}
	token, uid, err := serviceauth.WorkWXLogin(userID, traceID)
	if err != nil {
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}

	userInfo, err := serviceldap.GetUserInfoByUID(uid, []string{})
	conf.Logger.InfoW("weixin", map[string]interface{}{"userInfo": userInfo})
	if err != nil {
		net.Reply200(ctx, net.FailWithDetail(lib.CodeSignCheck, err.Error()))
		return
	}

	ctx.SetCookie(conf.CookieTicketKey, token, conf.CookieDefaultMaxAge, "",
		conf.C.LdapConfig.BaseDomain, false, false)
	ctx.SetCookie(conf.CookieLoginAdminKey, "0", conf.CookieDefaultMaxAge, "",
		conf.C.LdapConfig.BaseDomain, false, false)

	ctx.SetCookie(conf.CookieLoginUIDKey, strconv.FormatInt(userInfo[ldapapi.BaseInfoUidKey].(int64), 10), conf.CookieDefaultMaxAge, "",
		conf.C.LdapConfig.BaseDomain, false, false)
	ctx.SetCookie(conf.CookieLoginUserNameKey, userInfo[ldapapi.BaseInfoUserNameKey].(string), conf.CookieDefaultMaxAge, "",
		conf.C.LdapConfig.BaseDomain, false, false)
	ctx.SetCookie(conf.CookieLoginNickNameKey, userInfo[ldapapi.BaseInfoNickNameKey].(string), conf.CookieDefaultMaxAge, "",
		conf.C.LdapConfig.BaseDomain, false, false)

	ctx.Redirect(http.StatusTemporaryRedirect, req.RedirectURL)
}

//GetWXAttribute 获取企业微信二维码必须的信息
func GetWXAttribute(ctx *gin.Context) {
	resp := serviceauth.GetWXAttribute()
	net.Reply200(ctx, resp)
}

//RegisterAndLogin 注册并登录
func RegisterAndLogin(ctx *gin.Context) {
	req := &ldapapi.LoginReq{}
	traceID := ctx.GetString("traceID")
	if traceID == "" {
		traceID = uuid.NewV4().String()
	}
	var err error
	if err = ctx.ShouldBindJSON(req); err != nil {
		conf.Logger.ErrorW("bind json for LoginReq fail",
			map[string]interface{}{"err": err, "traceId": traceID})
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}
	err = serviceldap.Register(req.LoginName, req.LoginPwd, traceID)
	if err != nil {
		conf.Logger.ErrorW("register failed", map[string]interface{}{"name": req.LoginName, "password": req.LoginPwd, "traceID": traceID})
		net.Reply200(ctx, net.FailWithDetail(lib.CodeSrv, err.Error()))
		return
	}
	token, uid, err := serviceauth.Login(req.LoginName, req.LoginPwd)
	if err != nil {
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}
	err = servicedb.AddUser(uid, traceID)
	if err != nil {
		conf.Logger.ErrorW("add user error", map[string]interface{}{"error": err, "traceID": traceID})
	}
	userInfo, err := serviceldap.GetUserInfoByUID(uid, []string{})
	ctx.SetCookie(conf.CookieTicketKey, token, conf.CookieDefaultMaxAge, "",
		conf.C.LdapConfig.BaseDomain, false, false)
	URL := conf.C.DefaultRedirectURL
	if req.ReturnURL != "" {
		URL = req.ReturnURL
	}
	userInfo["url"] = URL
	userInfo["admin"] = "0"
	if req.LoginName == conf.C.ServerConfig.UserName {
		userInfo["admin"] = "1"
		userInfo["url"] = conf.C.DefaultRedirectURL
	}

	net.Reply200(ctx, net.OkWithData(userInfo))
}
