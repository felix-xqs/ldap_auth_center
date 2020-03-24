package tools

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"math/rand"
	"sort"
	"strings"
)

const letterBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

const (
	// ValidateSignatureError ...
	ValidateSignatureError int = -40001
	// ParseXMLError ...
	ParseXMLError          int = -40002
	// ComputeSignatureError ...
	ComputeSignatureError  int = -40003
	// IllegalAesKey ...
	IllegalAesKey          int = -40004
	// ValidateCorpidError ...
	ValidateCorpidError    int = -40005
	// EncryptAESError ...
	EncryptAESError        int = -40006
	// DecryptAESError ...
	DecryptAESError        int = -40007
	// IllegalBuffer ...
	IllegalBuffer          int = -40008
	// EncodeBase64Error ...
	EncodeBase64Error      int = -40009
	// DecodeBase64Error ...
	DecodeBase64Error      int = -40010
	// GenXMLError ...
	GenXMLError            int = -40010
	// ParseJSONError ...
	ParseJSONError         int = -40012
	// GenJSONError ...
	GenJSONError           int = -40013
	// IllegalProtocolType ...
	IllegalProtocolType    int = -40014
)

// ProtocolType ...
type ProtocolType int

const (
	// XMLType ...
	XMLType ProtocolType = 1
)

// CryptError ...
type CryptError struct {
	ErrCode int
	ErrMsg  string
}

// NewCryptError ...
func NewCryptError(errCode int, errMsg string) *CryptError {
	return &CryptError{ErrCode: errCode, ErrMsg: errMsg}
}

// WXBizMsg4Recv ...
type WXBizMsg4Recv struct {
	Tousername string `xml:"ToUserName"`
	Encrypt    string `xml:"Encrypt"`
	Agentid    string `xml:"AgentID"`
}

// CDATA ...
type CDATA struct {
	Value string `xml:",cdata"`
}

// WXBizMsg4Send ...
type WXBizMsg4Send struct {
	XMLName   xml.Name `xml:"xml"`
	Encrypt   CDATA    `xml:"Encrypt"`
	Signature CDATA    `xml:"MsgSignature"`
	Timestamp string   `xml:"TimeStamp"`
	Nonce     CDATA    `xml:"Nonce"`
}

// NewWXBizMsg4Send ...
func NewWXBizMsg4Send(encrypt, signature, timestamp, nonce string) *WXBizMsg4Send {
	return &WXBizMsg4Send{Encrypt: CDATA{Value: encrypt}, Signature: CDATA{Value: signature}, Timestamp: timestamp, Nonce: CDATA{Value: nonce}}
}

// ProtocolProcessor ...
type ProtocolProcessor interface {
	parse(srcData []byte) (*WXBizMsg4Recv, *CryptError)
	serialize(msgSend *WXBizMsg4Send) ([]byte, *CryptError)
}

// WXBizMsgCrypt ...
type WXBizMsgCrypt struct {
	token              string
	encodingAeskey    string
	receiverID        string
	protocolProcessor ProtocolProcessor
}

// XMLProcessor ...
type XMLProcessor struct {
}

func (xmlProc *XMLProcessor) parse(srcData []byte) (*WXBizMsg4Recv, *CryptError) {
	var msg4Recv WXBizMsg4Recv
	err := xml.Unmarshal(srcData, &msg4Recv)
	if nil != err {
		return nil, NewCryptError(ParseXMLError, "xml to msg fail")
	}
	return &msg4Recv, nil
}

func (xmlProc *XMLProcessor) serialize(msg4Send *WXBizMsg4Send) ([]byte, *CryptError) {
	xmlMsg, err := xml.Marshal(msg4Send)
	if nil != err {
		return nil, NewCryptError(GenXMLError, err.Error())
	}
	return xmlMsg, nil
}

// NewWXBizMsgCrypt ...
func NewWXBizMsgCrypt(token, encodingAeskey, receiverID string, protocolType ProtocolType) *WXBizMsgCrypt {
	var protocolProcessor ProtocolProcessor
	if protocolType != XMLType {
		panic("unsupport protocal")
	} else {
		protocolProcessor = new(XMLProcessor)
	}

	return &WXBizMsgCrypt{token: token, encodingAeskey: (encodingAeskey + "="), receiverID: receiverID, protocolProcessor: protocolProcessor}
}

// randString ...
func (wxBMC *WXBizMsgCrypt) randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func (wxBMC *WXBizMsgCrypt) pKCS7Padding(plaintext string, blockSize int) []byte {
	padding := blockSize - (len(plaintext) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	var buffer bytes.Buffer
	buffer.WriteString(plaintext)
	buffer.Write(padtext)
	return buffer.Bytes()
}

func (wxBMC *WXBizMsgCrypt) pKCS7Unpadding(plaintext []byte, blockSize int) ([]byte, *CryptError) {
	plaintextLen := len(plaintext)
	if nil == plaintext || plaintextLen == 0 {
		return nil, NewCryptError(DecryptAESError, "pKCS7Unpadding error nil or zero")
	}
	if plaintextLen%blockSize != 0 {
		return nil, NewCryptError(DecryptAESError, "pKCS7Unpadding text not a multiple of the block size")
	}
	paddingLen := int(plaintext[plaintextLen-1])
	return plaintext[:plaintextLen-paddingLen], nil
}

func (wxBMC *WXBizMsgCrypt) cbcEncrypter(plaintext string) ([]byte, *CryptError) {
	aeskey, err := base64.StdEncoding.DecodeString(wxBMC.encodingAeskey)
	if nil != err {
		return nil, NewCryptError(DecodeBase64Error, err.Error())
	}
	const blockSize = 32
	padMsg := wxBMC.pKCS7Padding(plaintext, blockSize)

	block, err := aes.NewCipher(aeskey)
	if err != nil {
		return nil, NewCryptError(EncryptAESError, err.Error())
	}

	ciphertext := make([]byte, len(padMsg))
	iv := aeskey[:aes.BlockSize]

	mode := cipher.NewCBCEncrypter(block, iv)

	mode.CryptBlocks(ciphertext, padMsg)
	base64Msg := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(base64Msg, ciphertext)

	return base64Msg, nil
}

func (wxBMC *WXBizMsgCrypt) cbcDecrypter(base64EncryptMsg string) ([]byte, *CryptError) {
	aeskey, err := base64.StdEncoding.DecodeString(wxBMC.encodingAeskey)
	if nil != err {
		return nil, NewCryptError(DecodeBase64Error, err.Error())
	}

	encryptMsg, err := base64.StdEncoding.DecodeString(base64EncryptMsg)
	if nil != err {
		return nil, NewCryptError(DecodeBase64Error, err.Error())
	}

	block, err := aes.NewCipher(aeskey)
	if err != nil {
		return nil, NewCryptError(DecryptAESError, err.Error())
	}

	if len(encryptMsg) < aes.BlockSize {
		return nil, NewCryptError(DecryptAESError, "encrypt_msg size is not valid")
	}

	iv := aeskey[:aes.BlockSize]

	if len(encryptMsg)%aes.BlockSize != 0 {
		return nil, NewCryptError(DecryptAESError, "encrypt_msg not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(encryptMsg, encryptMsg)

	return encryptMsg, nil
}

func (wxBMC *WXBizMsgCrypt) calSignature(timestamp, nonce, data string) string {
	sortArr := []string{wxBMC.token, timestamp, nonce, data}
	sort.Strings(sortArr)
	var buffer bytes.Buffer
	for _, value := range sortArr {
		buffer.WriteString(value)
	}

	sha := sha1.New()
	_, err := sha.Write(buffer.Bytes())
	if err != nil {
		return ""
	}
	signature := fmt.Sprintf("%x", sha.Sum(nil))
	return string(signature)
}

// ParsePlainText ...
func (wxBMC *WXBizMsgCrypt) ParsePlainText(plaintext []byte) ([]byte, uint32, []byte, []byte, *CryptError) {
	const blockSize = 32
	plaintext, err := wxBMC.pKCS7Unpadding(plaintext, blockSize)
	if nil != err {
		return nil, 0, nil, nil, err
	}

	textLen := uint32(len(plaintext))
	if textLen < 20 {
		return nil, 0, nil, nil, NewCryptError(IllegalBuffer, "plain is to small 1")
	}
	random := plaintext[:16]
	msgLen := binary.BigEndian.Uint32(plaintext[16:20])
	if textLen < (20 + msgLen) {
		return nil, 0, nil, nil, NewCryptError(IllegalBuffer, "plain is to small 2")
	}

	msg := plaintext[20 : 20+msgLen]
	receiverID := plaintext[20+msgLen:]

	return random, msgLen, msg, receiverID, nil
}

// VerifyURL ...
func (wxBMC *WXBizMsgCrypt) VerifyURL(msgSignature, timestamp, nonce, echostr string) ([]byte, *CryptError) {
	signature := wxBMC.calSignature(timestamp, nonce, echostr)

	if strings.Compare(signature, msgSignature) != 0 {
		return nil, NewCryptError(ValidateSignatureError, "signature not equal")
	}

	plaintext, err := wxBMC.cbcDecrypter(echostr)
	if nil != err {
		return nil, err
	}

	_, _, msg, receiverID, err := wxBMC.ParsePlainText(plaintext)
	if nil != err {
		return nil, err
	}

	if len(wxBMC.receiverID) > 0 && strings.Compare(string(receiverID), wxBMC.receiverID) != 0 {
		fmt.Println(string(receiverID), wxBMC.receiverID, len(receiverID), len(wxBMC.receiverID))
		return nil, NewCryptError(ValidateCorpidError, "receiver_id is not equil")
	}

	return msg, nil
}

// EncryptMsg ...
func (wxBMC *WXBizMsgCrypt) EncryptMsg(replyMsg, timestamp, nonce string) ([]byte, *CryptError) {
	randStr := wxBMC.randString(16)
	var buffer bytes.Buffer
	buffer.WriteString(randStr)

	msgLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLenBuf, uint32(len(replyMsg)))
	buffer.Write(msgLenBuf)
	buffer.WriteString(replyMsg)
	buffer.WriteString(wxBMC.receiverID)

	tmpCiphertext, err := wxBMC.cbcEncrypter(buffer.String())
	if nil != err {
		return nil, err
	}
	ciphertext := string(tmpCiphertext)

	signature := wxBMC.calSignature(timestamp, nonce, ciphertext)

	msg4Send := NewWXBizMsg4Send(ciphertext, signature, timestamp, nonce)
	return wxBMC.protocolProcessor.serialize(msg4Send)
}

// DecryptMsg ..
func (wxBMC *WXBizMsgCrypt) DecryptMsg(msgSignature, timestamp, nonce string, postData []byte) ([]byte, *CryptError) {
	msg4Recv, cryptErr := wxBMC.protocolProcessor.parse(postData)
	if nil != cryptErr {
		return nil, cryptErr
	}

	signature := wxBMC.calSignature(timestamp, nonce, msg4Recv.Encrypt)

	if strings.Compare(signature, msgSignature) != 0 {
		return nil, NewCryptError(ValidateSignatureError, "signature not equal")
	}

	plaintext, cryptErr := wxBMC.cbcDecrypter(msg4Recv.Encrypt)
	if cryptErr != nil {
		return nil, cryptErr
	}

	_, _, msg, receiverID, cryptErr := wxBMC.ParsePlainText(plaintext)
	if cryptErr != nil {
		return nil, cryptErr
	}

	if len(wxBMC.receiverID) > 0 && strings.Compare(string(receiverID), wxBMC.receiverID) != 0 {
		return nil, NewCryptError(ValidateCorpidError, "receiver_id is not equil")
	}

	return msg, nil
}
