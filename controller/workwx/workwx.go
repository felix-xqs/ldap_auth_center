package workwx

import (
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"net/http"
	"xgit.xiaoniangao.cn/devops/ldap_server/conf"
	"xgit.xiaoniangao.cn/devops/ldap_server/service/servicewx"
	"xgit.xiaoniangao.cn/devops/ldap_server/util/net"
	"xgit.xiaoniangao.cn/devops/ldap_server_api/ldapapi"
	"xgit.xiaoniangao.cn/xngo/lib/sdk/lib"
	"xgit.xiaoniangao.cn/xngo/lib/sdk/xng"
)

//WxEcho work weixin echo data
type WxEcho struct {
	MsgSignature string `json:"msg_signature" form:"msg_signature"`
	TimeStamp    int    `json:"timestamp" form:"timestamp"`
	Nonce        string `json:"nonce" form:"nonce"`
	EchoStr      string `json:"echostr" form:"echostr"`
}

//WxInfo Get work weixin info
type WxInfo struct {
	MsgSignature string `json:"msg_signature" form:"msg_signature"`
	TimeStamp    int    `json:"timestamp" form:"timestamp"`
	Nonce        string `json:"nonce" form:"nonce"`
}

//GetWXEcho get work weixin echostr analyze retrun Plaintext controller
func GetWXEcho(ctx *gin.Context) {
	req := &WxEcho{}
	traceID := ctx.GetString("traceID")
	if traceID == "" {
		traceID = uuid.NewV4().String()
	}

	if err := ctx.ShouldBindQuery(req); err != nil {
		conf.Logger.ErrorW("bind query for GetWXEcho fail",
			map[string]interface{}{"err": err, "traceId": traceID})
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}
	resp := servicewx.GetPlaintText(req.MsgSignature, req.TimeStamp, req.Nonce, req.EchoStr, traceID)
	//resp := ""
	ctx.String(http.StatusOK, resp)
}

//GetWXInfo get work weixin data
func GetWXInfo(ctx *gin.Context) {
	req := &WxInfo{}
	traceID := ctx.GetString("traceID")
	if traceID == "" {
		traceID = uuid.NewV4().String()
	}
	if err := ctx.ShouldBindQuery(req); err != nil {
		conf.Logger.ErrorW("bind for GetWXInfo fail", map[string]interface{}{"error": err, "traceId": traceID})
		//更改
		net.Reply200(ctx, net.FailWithDetail(lib.CodePara, err.Error()))
		return
	}
	reqData, err := ctx.GetRawData()
	if err != nil {
		conf.Logger.ErrorW("get wx callback data error", map[string]interface{}{"request data": reqData, "error": err, "traceID": traceID})
		//更改
		net.FailWithDetail(lib.CodePara, "")
		return
	}
	servicewx.GetMsgCallBack(req.MsgSignature, req.TimeStamp, req.Nonce, reqData, traceID)
}

//GetWXToken get work weixin accesstoken controller
func GetWXToken(ctx *gin.Context) {
	var req ldapapi.WorkWXTokenReq
	if !xc.GetReqObject(&req) {
		conf.Logger.Error("get wxtoken req error")
		return
	}
	traceID := ctx.GetString("traceID")
	if traceID == "" {
		traceID = uuid.NewV4().String()
	}
	if req.IsNeedUpdate < 0 {
		conf.Logger.ErrorW("get wx access token params parse error", map[string]interface{}{"getWXTokenReq": req, "traceID": traceID})
		xc.ReplyFail(lib.CodePara)
		return
	}

	resp := servicewx.GetWXAccessToken(req.CorpSecret, req.IsNeedUpdate, traceID)
	if len(resp) == 0 {
		conf.Logger.ErrorW("get wx accesstoken error", map[string]interface{}{"corpSecret": req.CorpSecret})
		xc.ReplyFail(lib.CodeSrv)
		return
	}
	xc.ReplyOK(resp)
}

//UpdateLdapInfo update ldap from work weixin
func UpdateLdapInfo(ctx *gin.Context) {

	traceID := ctx.GetString("traceID")
	if traceID == "" {
		traceID = uuid.NewV4().String()
	}
	err := servicewx.UpdateLdapInfo(traceID)
	if err != nil {
		net.Reply200(ctx, net.FailWithDetail(lib.CodeUpdateErr, "update fail"))
		return
	}
	net.Reply200(ctx, net.Ok())
}
