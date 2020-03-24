package net

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// Reply200 ...
func Reply200(ctx *gin.Context, resp *lib.Resp) {
	ctx.JSON(http.StatusOK, resp)

}

// FailWithDetail ...
func FailWithDetail(code lib.Code, detail string) *lib.Resp {
	return &lib.Resp{
		Ret:    code,
		Msg:    lib.CodeMap[code],
		Detail: detail,
	}
}

// FailWithMsg ...
func FailWithMsg(code lib.Code, msg string, detail string) *lib.Resp {
	return &lib.Resp{
		Ret:    code,
		Msg:    msg,
		Detail: detail,
	}
}

// OkWithData ...
func OkWithData(data interface{}) *lib.Resp {
	return &lib.Resp{
		Ret:  lib.CodeOk,
		Data: data,
	}
}

// Ok ...
func Ok() *lib.Resp {
	return &lib.Resp{
		Ret: lib.CodeOk,
	}
}

// Data ...
func Data(data interface{}) *lib.Resp {
	return &lib.Resp{
		Data: data,
	}
}
