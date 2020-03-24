package sendmail

import (
	"github.com/go-gomail/gomail"
)

// MailParam 邮件验证所需参数
type MailParam struct {
	Username string `json:"user"`
	Password string `json:"password"`
	Host string `json:"host"`
	Port int `json:"port"`
}

// MailInfo 邮件发送信息
type MailInfo struct {
	MailFrom string `json:"mailFrom"`
	MailTo []string `json:"mailTo"`
	Subject string `json:"subject"`
	Body MailBody `json:"body"`
}

// MailBody 邮件Body设定
type MailBody struct {
	Type BodyType `json:"type"`
	Content string `json:"content"`
}

// BodyType Body 类型
type BodyType string

const (
	// HTML ...
	HTML BodyType = "text/html"
	// Plain ...
	Plain BodyType = "text/plain"
)

// Send 发送邮件
func Send(mailParam *MailParam, mailInfo *MailInfo) (err error) {
	mail := gomail.NewMessage()
	mail.SetHeader("From",mailInfo.MailFrom + "<" + mailParam.Username + ">")
	mail.SetHeader("To", mailInfo.MailTo...)
	mail.SetHeader("Subject", mailInfo.Subject)
	mail.SetBody(string(mailInfo.Body.Type), mailInfo.Body.Content)

	dialer := gomail.NewDialer(mailParam.Host, mailParam.Port, mailParam.Username, mailParam.Password)
	if err = dialer.DialAndSend(mail); err !=nil{
		return
	}

	return
}
