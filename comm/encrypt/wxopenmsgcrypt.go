package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/log"
)

const (
	ValidateSignatureError int = -40001
	ParseXmlError          int = -40002
	ComputeSignatureError  int = -40003
	IllegalAesKey          int = -40004
	ValidateAppidError     int = -40005
	EncryptAESError        int = -40006
	DecryptAESError        int = -40007
	IllegalBuffer          int = -40008
	EncodeBase64Error      int = -40009
	DecodeBase64Error      int = -40010
)

func getErrorMsg(errorCode int) string {
	switch errorCode {
	case ValidateSignatureError:
		return "签名验证错误"
	case ParseXmlError:
		return "xml解析失败"
	case ComputeSignatureError:
		return "sha加密生成签名失败"
	case IllegalAesKey:
		return "SymmetricKey非法"
	case ValidateAppidError:
		return "appid校验失败"
	case EncryptAESError:
		return "aes加密失败"
	case DecryptAESError:
		return "aes解密失败"
	case IllegalBuffer:
		return "解密后得到的buffer非法"
	case EncodeBase64Error:
		return "base64加密错误"
	case DecodeBase64Error:
		return "base64解密错误"
	default:
		return "未知错误"
	}
}

var encodingAeskey string
var token string

func init() {
	// token = os.Getenv("WX_TOKEN")
	// encodingAeskey = os.Getenv("WX_AES_KEY")
	token = "token"
	encodingAeskey = "DWmNgZds5ySvyFHJU840Fo6PZ0LMPbGvCbrto0uAmOz"
}

type WxOpenMsgCrypt struct {
	token          string
	encodingAeskey string
	appid          string
}

func NewWxOpenMsgCrypt(appid string) *WxOpenMsgCrypt {
	return &WxOpenMsgCrypt{token: token, encodingAeskey: encodingAeskey, appid: appid}
}

// 验证消息回调内容
func (self *WxOpenMsgCrypt) VerifyUrl(msgSignature, timStamp, nonce, echoStr string) ([]byte, error) {
	signature := self.getSha1(timStamp, nonce, echoStr)
	if strings.Compare(signature, msgSignature) != 0 {
		return nil, errors.New(getErrorMsg(ValidateSignatureError))
	}

	// 对消息密文进行解密
	plaintext, err := self.cbcDecrypter(echoStr)
	if err != nil {
		return nil, err
	}

	// 对消息明文进行解析
	_, _, msg, fromAppid, err := self.ParsePlainText(plaintext)
	if err != nil {
		return nil, err
	}

	// appid 始终是服务商的appid吗
	if len(self.appid) > 0 && strings.Compare(self.appid, string(fromAppid)) != 0 {
		fmt.Println(string(fromAppid), self.appid, len(fromAppid), len(self.appid))
		return nil, errors.New(getErrorMsg(ValidateAppidError))
	}

	return msg, nil
}

func (self *WxOpenMsgCrypt) getSha1(timStamp, nonce, echoStr string) string {
	slice := []string{self.token, timStamp, nonce, echoStr}
	sort.Strings(slice)
	sortedString := strings.Join(slice, "")

	sha := sha1.New()
	sha.Write([]byte(sortedString))
	shaBytes := sha.Sum(nil)

	var signatureBuild strings.Builder
	for _, v := range shaBytes {
		shaHex := fmt.Sprintf("%x", (v & 0xff))
		if len(shaHex) < 2 {
			signatureBuild.Write([]byte("0"))
		}
		signatureBuild.Write([]byte(shaHex))
	}
	return signatureBuild.String()
}

// 验证并解密密文
func (self *WxOpenMsgCrypt) cbcDecrypter(base64EncryptMsg string) ([]byte, error) {
	aeskey, err := base64.StdEncoding.DecodeString(self.encodingAeskey + "=")
	if err != nil {
		return nil, errors.New(getErrorMsg(DecodeBase64Error))
	}
	// aeskey := []byte(self.encodingAeskey)

	encryptMsg, err := base64.StdEncoding.DecodeString(base64EncryptMsg)
	if nil != err {
		return nil, errors.New("decode encrypt msg failed")
	}

	block, err := aes.NewCipher(aeskey)
	if err != nil {
		log.Debugf("encodingAeskey :%s, aesKey :%s", self.encodingAeskey, aeskey)
		log.Errorf("创建Cipher异常 error msg :%s", err)
		return nil, errors.New("new Ciper error")
	}

	if len(encryptMsg) < aes.BlockSize {
		return nil, errors.New("encryptMsg size is not valid")
	}

	iv := aeskey[:aes.BlockSize]

	if len(encryptMsg)%aes.BlockSize != 0 {
		return nil, errors.New("encryptMsg not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(encryptMsg, encryptMsg)

	return encryptMsg, nil
}

func (self *WxOpenMsgCrypt) ParsePlainText(plaintext []byte) ([]byte, uint32, []byte, []byte, error) {
	const blockSize = 32
	plaintext, err := self.PKCS7Unpadding(plaintext, blockSize)
	if nil != err {
		return nil, 0, nil, nil, err
	}

	textLen := uint32(len(plaintext))
	if textLen < 20 {
		return nil, 0, nil, nil, errors.New("plain is to small 1")
	}
	// 作用未知
	random := plaintext[:16]
	// 消息内容长度
	msgLen := binary.BigEndian.Uint32(plaintext[16:20])
	if textLen < (20 + msgLen) {
		return nil, 0, nil, nil, errors.New("plain length not match")
	}

	// 消息内容
	msg := plaintext[20 : 20+msgLen]

	// 事件来源appid
	fromAppid := plaintext[20+msgLen:]

	return random, msgLen, msg, fromAppid, nil
}

func (self *WxOpenMsgCrypt) PKCS7Unpadding(plaintext []byte, block_size int) ([]byte, error) {
	plaintextLen := len(plaintext)
	if nil == plaintext || plaintextLen == 0 {
		return nil, errors.New("pKCS7Unpadding error nil or zero")
	}
	if plaintextLen%block_size != 0 {
		return nil, errors.New("pKCS7Unpadding text not a multiple of the block size")
	}
	padding_len := int(plaintext[plaintextLen-1])
	return plaintext[:plaintextLen-padding_len], nil
}
