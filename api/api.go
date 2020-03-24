package api

//UserDetailsReq  Get User Details Req
type UserDetailsReq struct {
	Token string `json:"token"`
	UID   int64  `json:"uid"`
}

//UserDetails data in ldap,mongo,workwx，userid，name,email,
type UserDetails struct {
	UserID     int64    `json:"uid"`
	UserName   string   `json:"userName"`
	Department []string `json:"department"`
	Position   string   `json:"position"`
	Email      string   `json:"email"`
	Gender     string   `json:"gender"`
	Avatar     string   `json:"avatar"`
	Mobile     string   `json:"mobile"`
	QrCode     string   `json:"qrCode"`
	WorkStatus string   `json:"workStatus"`
	WorkPlace  string   `json:"workPlace"`
}

//SearchReq search request data
type SearchReq struct {
	SearchInfo string `json:"searchInfo"`
}

//PasswordReq update password req
type PasswordReq struct {
	UserName string `json:"userName" binding:"required"`
	OldPwd   string `json:"oldPwd" binding:"required"`
	NewPwd   string `json:"newPwd" binding:"required"`
}

//EventContent work wx 回调信息结构体
type EventContent struct {
	ToUsername   string `xml:"ToUserName"`
	FromUsername string `xml:"FromUserName"`
	CreateTime   uint32 `xml:"CreateTime"`
	MsgType      string `xml:"MsgType"`
	Event        string `xml:"Event"`
	ChangeType   string `xml:"ChangeType"`
	UserID       string `xml:"UserID"`
	NewUserID    string `xml:"NewUserID"`
	Name         string `xml:"Name"`
	Mobile       string `xml:"Mobile"`
	Email        string `xml:"Email"`
}

//UserInfoUpdateReq 更新mongo信息的req
type UserInfoUpdateReq struct {
	UID  int64        `json:"uid" binding:"required"`
	Data *UserMgoInfo `json:"data" binding:"required"`
}

//UserMgoInfo mongo中信息的结构体
type UserMgoInfo struct {
	UserID     int64 `json:"userID" binding:"required"`
	WorkStatus int   `json:"workStatus"`
	WorkPlace  int   `json:"workPlace"`
}

//WorkWXAttributeResp 获取企业微信扫码所需信息的resp
type WorkWXAttributeResp struct {
	AppID   string `json:"appId"`
	AgentID string `json:"agentId"`
	State   string `json:"state"`
}

//WorkWXScanReq 二维码属性
type WorkWXScanReq struct {
	RedirectURL string `json:"redirect_url" form:"redirect_url"`
	State       string `json:"state" form:"state"`
	Code        string `json:"code" form:"code"`
}

//UserAuthReq 用户认证请求
type UserAuthReq struct {
	LoginName string `json:"loginName"`
}

//UserAuthResp  认证返回值
type UserAuthResp struct {
	Auth int `json:"auth"`
}

//UserPwdVerifyReq ...
type UserPwdVerifyReq struct {
	Password string `json:"loginPwd"`
}
