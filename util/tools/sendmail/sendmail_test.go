package sendmail

import (
	"fmt"
	"testing"
)

func TestSendMail(t *testing.T) {
	mailParam := new(MailParam)
	mailParam.Host = "smtp.exmail.qq.com"
	mailParam.Port = 465
	mailParam.Username = "zangkuo@xiaoniangao.com"
	mailParam.Password = ""

	mailInfo := new(MailInfo)
	mailInfo.MailTo = []string{"zangkuo@xiaoniangao.com"}
	mailInfo.Subject = "Hello by golang gomail from exmail.qq.com"
	mailInfo.Body.Type = HTML
	mailInfo.Body.Content = `<div><font color="red">Hello,by gomail sent</font></div>`

	if err := Send(mailParam, mailInfo); err!=nil {
		fmt.Println(err)
		return
	}

	return

}
