package middleware

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/encrypt"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/errno"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/log"
	"github.com/gin-gonic/gin"
)

type wxCallbackCommonRecord struct {
	AppId   string `xml:"AppId"`
	Encrypt string `xml:"Encrypt"`
}

type wxCallbackCommonBizRecord struct {
	AppId                        string `xml:"AppId" json:"AppId"`
	CreateTime                   int64  `xml:"CreateTime" json:"CreateTime"`
	InfoType                     string `xml:"InfoType" json:"InfoType"`
	ComponentVerifyTicket        string `xml:"ComponentVerifyTicket" json:"ComponentVerifyTicket"`
	AuthorizerAppid              string `xml:"AuthorizerAppid" json:"AuthorizerAppid"`
	AuthorizationCode            string `xml:"AuthorizationCode" json:"AuthorizationCode"`
	AuthorizationCodeExpiredTime int64  `xml:"AuthorizationCodeExpiredTime" json:"AuthorizationCodeExpiredTime"`
	ToUserName                   string `xml:"ToUserName" json:"ToUserName"`
	MsgType                      string `xml:"MsgType" json:"MsgType"`
	Event                        string `xml:"Event" json:"Event"`
}

// WXOpenSourceMiddleWare 中间件 用于处理域名方式回调，兼容内网
func WXOpenSourceMiddleWare(c *gin.Context) {
	if _, ok := c.Request.Header[http.CanonicalHeaderKey("x-wx-source")]; ok {
		fmt.Println("[WXOpenSourceMiddleWare]from wx")
		c.Next()
	} else {
		body, _ := ioutil.ReadAll(c.Request.Body)
		log.Debugf("encryptedBody: %s", string(body))
		// 不是内网模式，对消息进行校验
		timestamp := c.Query("timestamp")
		nonce := c.Query("nonce")
		signature := c.Query("signature")
		encryptType := c.Query("encrypt_type")
		msgSignature := c.Query("msg_signature")
		log.Debugf("timestamp: %s, nonce: %s, signature: %s, encryptType: %s, msgSignature: %s", timestamp, nonce, signature, encryptType, msgSignature)

		if timestamp == "" || nonce == "" || signature == "" || encryptType == "" || msgSignature == "" {
			log.Error("请求格式错误, imestamp: %s, nonce: %s, signature: %s, encryptType: %s, msgSignature: %s", timestamp, nonce, signature, encryptType, msgSignature)
			c.Abort()
			c.JSON(http.StatusBadRequest, errno.ErrInvalidParam)
			return
		}

		if !strings.EqualFold("aes", encryptType) {
			log.Errorf("[WXOpenSourceMiddleWare]unsupported encrypt type: %s", encryptType)
			c.Abort()
			c.JSON(http.StatusBadRequest, errno.ErrInvalidParam)
			return
		}

		// 将xml格式body转换为struct，供解密使用
		rawEvent := wxCallbackCommonRecord{}
		err := xml.Unmarshal([]byte(body), &rawEvent)
		if err != nil {
			log.Errorf("解析原始事件失败 error msg :%s", err)
			c.Abort()
			c.JSON(http.StatusBadRequest, errno.ErrInvalidParam)
			return
		}

		// 验证消息并解密
		wxOpenMsgCrypt := encrypt.NewWxOpenMsgCrypt(rawEvent.AppId)
		msg, err := wxOpenMsgCrypt.VerifyUrl(msgSignature, timestamp, nonce, rawEvent.Encrypt)
		if err != nil {
			log.Errorf("[WXOpenSourceMiddleWare] decrypt failed, rawEvent: %s, error msg: %s", rawEvent, err)
			c.Abort()
			c.JSON(http.StatusBadRequest, errno.ErrInvalidParam)
			return
		}

		// xml 无结构化转成json 让下游继续按照json格式处理业务 todo 无结构转换，不hardcode结构体
		log.Debugf("消息明文: %s", msg)

		bizRecord := wxCallbackCommonBizRecord{}
		error := xml.Unmarshal(msg, &bizRecord)
		if error != nil {
			log.Errorf("[WXOpenSourceMiddleWare] unserializable failed, error msg: %s", error)
			c.Abort()
			c.JSON(http.StatusBadRequest, errno.ErrInvalidParam)
			return
		}
		log.Debugf("xml消息明文: %s", bizRecord)
		json, err := json.Marshal(bizRecord)
		if err != nil {
			log.Errorf("[WXOpenSourceMiddleWare] serializable json failed, error msg: %s", err)
			c.Abort()
			c.JSON(http.StatusBadRequest, errno.ErrInvalidParam)
			return
		}
		log.Debugf("json消息明文: %s", json)

		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(json))
	}
}
