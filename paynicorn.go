package paynicorn

import (
	"crypto/md5"
    "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
    "bytes"
    "time"
    "errors"
	"io/ioutil"
	"net/http"
	"strings"
)

var(
	SUCCESS_CODE = "000000"
)

type TxnTypeEnum string

const (
	PAYMENT TxnTypeEnum = "payment"

	PAYOUT TxnTypeEnum = "payout"

	AUTHPAY TxnTypeEnum = "authpay"

	REFUND TxnTypeEnum = "refund"

	SUBSCRIBE TxnTypeEnum = "subscribe"
)

/**
request body struct
content is the base64 string of request json data
sign is the md5 value of content

 */
type RequestBody struct{
	Content string `json:"content"`
	Sign string `json:"sign"`
	AppKey string `json:"appKey"`
}

/**
paynicorn response body struct
 */
type ResponseBody struct{
	ResponseCode string `json:"responseCode"`
	ResponseMessage string `json:"responseMessage"`
	Content string `json:"content"`
	Sign string `json:"sign"`
}


type PostbackInfo struct{
	Verified bool
	TxnId string `json:"txnId"`
	OrderId string `json:"orderId"`
	Amount string `json:"amount"`
	Currency string `json:"currency"`
	CountryCode string `json:"countryCode"`
	Status string `json:"status"`
	Code string `json:"code"`
	Message string `json:"message"`
}

type PostbackRequest struct{
	Content string `json:"content"`
	Sign string `json:"sign"`
}

/**
query  transaction status request
 */
type QueryPaymentRequest struct{
	OrderId string `json:"orderId"`//MANDATORY unique transaction id generate by paynicorn.you can use it to query your transaction status or wait for a postback
	TxnType  TxnTypeEnum `json:"txnType"`
}

/**
query  transaction status response
 */
type QueryPaymentResponse struct{

	Code	string    `json:"code"` // MANDATORY response code represent current request is success response or not refer to https://www.paynicorn.com/#/docs 6.5

	Message	string `json:"message"` //	MANDATORY response code refer to https://www.paynicorn.com/#/docs 6.5

	TxnId	string `json:"txnId"`//	MANDATORY unique transaction id generate by paynicorn.you can use it to query your transaction status or wait for a postback

	Status	string `json:"status"`//	OPTIONAL transaction status (1:for success；-1：processing；0：failure)

	CompleteTime	string `json:"completeTime"` //OPTIONAL transaction complete time
}

/**
cashier payment request model
*/
type InitPaymentRequest struct {
	Amount string `json:"amount"`//mandatory ,local currency for a country.the range of amount is depend on currency.refer to develop docs https://www.paynicorn.com/#/docs 6.1

	CountryCode string `json:"countryCode"` //mandatory,country code define in iso 3166 alpha-2 code ，refer to develop docs https://www.paynicorn.com/#/docs 6.1

	Currency string `json:"currency"` //mandatory, currency short cod define in iso4217，refer to https://www.paynicorn.com/#/docs 6.1

	OrderId string `json:"orderId"`//mandatory,unique id for a transaction，if a request has the same orderId as an old request.you will get the same response as old request.

	OrderDescription string `json:"orderDescription"` //mandatory,this field will show on paynicorn cashier

	PayMethod string `json:"payMethod"`//optional, payment method refer to https://www.paynicorn.com/#/docs 6.3 if this filed is set paynicorn will use the payment method you set,otherwise paynicorn will show all available payment method on cashier

	Language string `json:"language"`//optional,default paynicorn will set language as user device local language.if you set we use it

	CpFrontPage string `json:"cpFrontPage"`//optional,if a payment is done ,paynicorn will redirect to this uri.

	UserId string `json:"userId"`//optional,deprecated

	Email string `json:"email"`//optional,user email kyc required

	Phone string `json:"phone"`//optional,user phone kyc required

	PayByLocalCurrency string `json:"payByLocalCurrency"`//optional ,if you use just one currency to price all your service or goods set it true paynicorn will change your currency to local currency

	Memo string `json:"memo"`//optional,you send it to paynicorn,paynicorn will return it back.
}

/**
raise cashier response
*/
type InitPaymentResponse struct {

	Code	string    `json:"code"` // MANDATORY response code represent current request is success response or not refer to https://www.paynicorn.com/#/docs 6.5

	Message	string `json:"message"` //	OPTIONAL response code refer to https://www.paynicorn.com/#/docs 6.5

	TxnId	string `json:"txnId"`//	OPTIONAL unique transaction id generate by paynicorn.you can use it to query your transaction status or wait for a postback

	Status	string `json:"status"`//	OPTIONAL transaction status (1:for success；-1：processing；0：failure)

	WebUrl	string `json:"webUrl"`//	OPTIONAL paynicorn cashier uri

}

type MethodInfo struct {
	Code string `json:"code"`
	Name string `json:"name"`
	Icon string `json:"icon"`
	MethodType string `json:"methodType"`
	SupportAmount []string `json:"supportAmount"`
	MinAmount float32 `json:"minAmount"`
	MaxAmount float32 `json:"maxAmount"`
	Discount float32 `json:"discount"`
}

type QueryMethodRequest struct {
	CountryCode string `json:"countryCode"`
	Currency string `json:"currency"`
	TxnType TxnTypeEnum `json:"txnType"`
}

type QueryMethodResponse struct {
	Code string `json:"code"`
	Message string `json:"message"`
	MethodInfo []MethodInfo `json:"methodInfo"`
}


/**
raise a payment cashier，most time you will get a web url and you need to open it in webview or browse
appKey ：merchant creat a app will get a appKey,refer to https://console.paynicorn.com/#/app/apply
merchantSecret ：merchant's secret use it to sign your data ,refer to https://console.paynicorn.com/#/developer
InitPaymentRequest ：raise an online payment cashier parameters
 */
func InitPayment(appKey string,merchantSecret string,request InitPaymentRequest)*InitPaymentResponse{

	url := "https://api.paynicorn.com/trade/v3/transaction/pay"
	jsonStr,_ :=json.Marshal(request)
	requestBody := RequestBody{}

	requestBody.Content = base64.StdEncoding.EncodeToString(jsonStr)
	requestBody.Sign = fmt.Sprintf("%x",md5.Sum([]byte(requestBody.Content+merchantSecret)))
	requestBody.AppKey = appKey

	client := &http.Client{}
	jsonBytes, _ := json.Marshal(requestBody)
	postRequest, _ := http.NewRequest("POST", url, strings.NewReader(string(jsonBytes)))
	postRequest.Header.Add("Content-Type", "application/json")

    log.Println("InitPayment req", string(jsonBytes))

	var buffer []byte
    response, err := client.Do(postRequest)
	if err == nil {

        buffer, err = ioutil.ReadAll(response.Body)
		if err == nil {
			rsp := ResponseBody{}
			err = json.Unmarshal(buffer, &rsp)

            log.Println("InitPayment res", string(buffer))
			if rsp.ResponseCode == SUCCESS_CODE{

				if sign := fmt.Sprintf("%x",md5.Sum([]byte(rsp.Content+merchantSecret))); sign == rsp.Sign{

					content, err := base64.StdEncoding.DecodeString(rsp.Content)
					if err == nil {
						rsp := InitPaymentResponse{}
						err = json.Unmarshal([]byte(content),&rsp)
						if err == nil{
							return &rsp
						}
					}
				}
			}
		} else {
            log.Println("InitPayment err", err.Error())
        }
	} else {
        log.Println("InitPayment err", err.Error())
    }

	return nil
}


func QueryPayment(appKey string,merchantSecret string,request QueryPaymentRequest) *QueryPaymentResponse {


	url := "https://api.paynicorn.com/trade/v3/transaction/query"
	jsonStr,_ := json.Marshal(request)
	requestBody := RequestBody{}

	requestBody.Content =  base64.StdEncoding.EncodeToString(jsonStr)
	requestBody.Sign = fmt.Sprintf("%x",md5.Sum([]byte(requestBody.Content+merchantSecret)))
	requestBody.AppKey = appKey

	client := &http.Client{}
	jsonBytes, _ := json.Marshal(requestBody)
	postRequest, _ := http.NewRequest("POST", url, strings.NewReader(string(jsonBytes)))
	postRequest.Header.Add("Content-Type", "application/json")

    log.Println("QueryPayment req", string(jsonBytes))

	var buffer []byte
    response, err := client.Do(postRequest)
	if err == nil {
        buffer, err = ioutil.ReadAll(response.Body)
		if err == nil {
			rsp := ResponseBody{}
			err = json.Unmarshal(buffer, &rsp)

            log.Println("QueryPayment res", string(buffer))
			if rsp.ResponseCode == SUCCESS_CODE{

				if sign := fmt.Sprintf("%x",md5.Sum([]byte(rsp.Content+merchantSecret))); sign == rsp.Sign{

					content, err := base64.StdEncoding.DecodeString(rsp.Content)
					if err == nil {
						rsp := QueryPaymentResponse{}
						err = json.Unmarshal(content, &rsp)
						if err == nil{
							return &rsp
						}
					}
				}
			}
		} else {
            log.Println("QueryPayment err", err.Error())
        }
	} else {
        log.Println("QueryPayment err", err.Error())
    }
	return nil
}


func ReceivePostback(merchantSecret string,request PostbackRequest) *PostbackInfo{

	response := PostbackInfo{}
	response.Verified = false

	if s := fmt.Sprintf("%x",md5.Sum([]byte(request.Content+merchantSecret))); request.Sign == s{

		c, err := base64.StdEncoding.DecodeString(request.Content)

		if err == nil {
			err = json.Unmarshal(c,&response)
			if err == nil{
				response.Verified = true
				return &response
			}
		}
	}

	return nil

}

func QueryMethod(appKey string,merchantSecret string,request QueryMethodRequest) *QueryMethodResponse{

	url := "https://api.paynicorn.com/trade/v3/transaction/method"
	jsonStr,_ := json.Marshal(request)
	requestBody := RequestBody{}

	requestBody.Content =  base64.StdEncoding.EncodeToString(jsonStr)
	requestBody.Sign = fmt.Sprintf("%x",md5.Sum([]byte(requestBody.Content+merchantSecret)))
	requestBody.AppKey = appKey

	client := &http.Client{}
	jsonBytes, _ := json.Marshal(requestBody)
	postRequest, _ := http.NewRequest("POST", url, strings.NewReader(string(jsonBytes)))
	postRequest.Header.Add("Content-Type", "application/json")

	var buffer []byte
	if response, err := client.Do(postRequest); err == nil {
		if buffer, err = ioutil.ReadAll(response.Body); err == nil {
			rsp := ResponseBody{}
			err = json.Unmarshal(buffer, &rsp)

			if rsp.ResponseCode == SUCCESS_CODE{

				if sign := fmt.Sprintf("%x",md5.Sum([]byte(rsp.Content+merchantSecret))); sign == rsp.Sign{

					content, err := base64.StdEncoding.DecodeString(rsp.Content)
					if err == nil {
						rsp := QueryMethodResponse{}
						err = json.Unmarshal(content, &rsp)
						if err == nil{
							return &rsp
						}
					}
				}
			}
		}
	}
	return nil
}

//认证
type PaynicornAccessTokenRes struct {
    Code                string  `json:"code,omitempty"`
    Message             string  `json:"message"`
    OpenId              string  `json:"openId"`
    AccessToken         string  `json:"accessToken"`
    AccessTokenExpire   int64   `json:"accessTokenExpire"`
    RefreshToken        string  `json:"refreshToken"`
    RefreshTokenExpire  int64   `json:"refreshTokenExpire"`
}

func GetAccessToken(appKey string, merchantSecret string, authCode string) (res *PaynicornAccessTokenRes, err error) {

	log.Println("GetPaynicornAccessToken", authCode)

    jsonStr := fmt.Sprintf(`{"authCode":"%s","appKey":"%s"}`, authCode, appKey)

    requestBody := RequestBody{}

	requestBody.Content =  base64.StdEncoding.EncodeToString([]byte(jsonStr))
	requestBody.Sign = fmt.Sprintf("%x",md5.Sum([]byte(requestBody.Content+merchantSecret)))
	requestBody.AppKey = appKey

	jsonBytes, _ := json.Marshal(requestBody)
	req, err := http.NewRequest("POST", "https://api.paynicorn.com/trade/customer/oauth/getAccessToken", bytes.NewBuffer(jsonBytes))
    if err != nil {
		log.Println("GetPaynicornAccessToken", err.Error())
		return res, err
	}
	req.Header.Set("Content-Type", "application/json")

    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //不验证ca证书，否则卡在这里
    client := &http.Client{Timeout: time.Duration(time.Second*10), Transport: tr}
	response, err := client.Do(req)
	if err != nil {
		log.Println("GetPaynicornAccessToken", err.Error())
		return res, err
	}
	defer response.Body.Close()
	resbytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("GetPaynicornAccessToken", err.Error())
		return res, err
	}

	log.Println("GetPaynicornAccessToken", string(resbytes))
    rsp := ResponseBody{}
	err = json.Unmarshal(resbytes, &rsp)
    if err != nil {
		log.Println("GetPaynicornAccessToken", err.Error())
		return nil, err
    }
    if rsp.ResponseCode != SUCCESS_CODE {
	    log.Println("GetPaynicornAccessToken", rsp.ResponseCode, "message", rsp.ResponseMessage)
		return nil, errors.New(rsp.ResponseMessage)
    }
    sign := fmt.Sprintf("%x",md5.Sum([]byte(rsp.Content+merchantSecret)))
    if sign != rsp.Sign {
	    log.Println("GetPaynicornAccessToken", rsp.ResponseCode, "message", rsp.ResponseMessage)
		return nil, errors.New(rsp.ResponseMessage)
    }

    content, err := base64.StdEncoding.DecodeString(rsp.Content)
    if err != nil {
		log.Println("GetPaynicornAccessToken", err.Error())
		return nil, err
    }
    res = &PaynicornAccessTokenRes{}
    err = json.Unmarshal([]byte(content), res)
    if err != nil{
		log.Println("GetPaynicornAccessToken", err.Error())
		return nil, err
	}
	return res, nil
}

type PaynicornUserinfoRes struct {
    Code                string  `json:"code,omitempty"`
    Message             string  `json:"message"`
    OpenId              string  `json:"openId"`
    Phone               string  `json:"phone"`
    AreaCode            string  `json:"areaCode"`
    CountryCode         string  `json:"countryCode"`
}

func GetUserinfo(appKey string, merchantSecret string, accessToken string) (res *PaynicornUserinfoRes, err error) {

	log.Println("GetPaynicornUserinfo", accessToken)
    jsonStr := fmt.Sprintf(`{"accessToken":"%s","appKey":"%s"}`, accessToken, merchantSecret)

    requestBody := RequestBody{}

	requestBody.Content =  base64.StdEncoding.EncodeToString([]byte(jsonStr))
	requestBody.Sign = fmt.Sprintf("%x",md5.Sum([]byte(requestBody.Content+merchantSecret)))
	requestBody.AppKey = appKey

	jsonBytes, _ := json.Marshal(requestBody)

	req, err := http.NewRequest("POST", "https://api.paynicorn.com/trade/customer/oauth/getUserInfo", bytes.NewBuffer(jsonBytes))
	if err != nil {
		log.Println("GetPaynicornUserinfo", err.Error())
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //不验证ca证书，否则卡在这里
    client := &http.Client{Timeout: time.Duration(time.Second*10), Transport: tr}
	response, err := client.Do(req)
	if err != nil {
		log.Println("GetPaynicornUserinfo", err.Error())
		return nil, err
	}
	defer response.Body.Close()
	resbytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("GetPaynicornUserinfo", err.Error())
		return nil, err
	}

	log.Println("GetPaynicornUserinfo", string(resbytes))
    rsp := ResponseBody{}
    err = json.Unmarshal(resbytes, &rsp)
    if err != nil {
		log.Println("GetPaynicornUserinfo", err.Error())
		return nil, err
    }
    log.Println("GetPaynicornUserinfo res", string(resbytes))
    if rsp.ResponseCode != SUCCESS_CODE {
	    log.Println("GetPaynicornUserinfo", rsp.ResponseCode, "message", rsp.ResponseMessage)
		return nil, errors.New(rsp.ResponseMessage)
    }
    sign := fmt.Sprintf("%x",md5.Sum([]byte(rsp.Content+merchantSecret)))
    if sign != rsp.Sign {
	    log.Println("GetPaynicornUserinfo", rsp.ResponseCode, "message", rsp.ResponseMessage)
		return nil, errors.New(rsp.ResponseMessage)
    }

    content, err := base64.StdEncoding.DecodeString(rsp.Content)
    if err != nil {
		log.Println("GetPaynicornUserinfo", err.Error())
		return nil, err
    }
    res = &PaynicornUserinfoRes{}
    err = json.Unmarshal([]byte(content), res)
    if err != nil{
		log.Println("GetPaynicornUserinfo", err.Error())
		return nil, err
	}
	return res, nil
}

//取款
type PaynicornTransReq struct {
    OrderId             string  `json:"orderId"`
    Currency            string  `json:"currency"`
    Amount              string  `json:"amount"`
    CountryCode         string  `json:"countryCode"`
    Name                string  `json:"name"`
    OpenId              string  `json:"openId"`
}
type PaynicornTransRes struct {
    Code                string  `json:"code"`
    Message             string  `json:"message"`
    Status              string  `json:"status"`
    TxnId               string  `json:"txnId"`
}

func Trans(appKey string, merchantSecret string, req *PaynicornTransReq) (res *PaynicornTransRes, err error) {

    jsonBytes, _ := json.Marshal(req)
	log.Println("PaynicornTrans", string(jsonBytes))

    requestBody := RequestBody{}
	requestBody.Content =  base64.StdEncoding.EncodeToString(jsonBytes)
	requestBody.Sign = fmt.Sprintf("%x",md5.Sum([]byte(requestBody.Content+merchantSecret)))
	requestBody.AppKey = appKey

	jsonBytes, _ = json.Marshal(requestBody)

	httpreq, err := http.NewRequest("POST", "https://api.paynicorn.com/trade/customer/oauth/transaction/payout", bytes.NewBuffer(jsonBytes))
	if err != nil {
		log.Println("PaynicornTrans", err.Error())
		return res, err
	}
	httpreq.Header.Set("Content-Type", "application/json")

    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //不验证ca证书，否则卡在这里
    client := &http.Client{Timeout: time.Duration(time.Second*10), Transport: tr}
	response, err := client.Do(httpreq)
	if err != nil {
		log.Println("PaynicornTrans", err.Error())
		return res, err
	}
	defer response.Body.Close()
	resbytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("PaynicornTrans", err.Error())
		return res, err
	}

	log.Println("PaynicornTrans", string(resbytes))
    
    rsp := ResponseBody{}
    err = json.Unmarshal(resbytes, &rsp)
    if err != nil {
		log.Println("PaynicornTrans", err.Error())
		return nil, err
    }

    log.Println("PaynicornTrans res", string(resbytes))
    if rsp.ResponseCode != SUCCESS_CODE {
	    log.Println("PaynicornTrans", rsp.ResponseCode, "message", rsp.ResponseMessage)
		return nil, errors.New(rsp.ResponseMessage)
    }
    sign := fmt.Sprintf("%x",md5.Sum([]byte(rsp.Content+merchantSecret)))
    if sign != rsp.Sign {
	    log.Println("PaynicornTrans", rsp.ResponseCode, "message", rsp.ResponseMessage)
		return nil, errors.New(rsp.ResponseMessage)
    }

    content, err := base64.StdEncoding.DecodeString(rsp.Content)
    if err != nil {
		log.Println("PaynicornTrans", err.Error())
		return nil, err
    }
    res = &PaynicornTransRes{}
    err = json.Unmarshal([]byte(content), res)
    if err != nil{
		log.Println("PaynicornTrans", err.Error())
		return nil, err
	}
	return res, nil
}

//取款通知

type PaynicornTransNoticeReq struct {
	Verified bool
    TxnId               string  `json:"txnId"`
    OrderId             string  `json:"orderId"`
    Amount              string  `json:"amount"`
    Currency            string  `json:"currency"`
    CountryCode         string  `json:"countryCode"`
    Status              string  `json:"status"`
    Code                string  `json:"code"`
    Message             string  `json:"message"`
    Memo                string  `json:"memo"`
}

func TransReceivePostback(merchantSecret string,request PostbackRequest) *PaynicornTransNoticeReq{

	response := PaynicornTransNoticeReq{}
	response.Verified = false

	if s := fmt.Sprintf("%x",md5.Sum([]byte(request.Content+merchantSecret))); request.Sign == s{

		c, err := base64.StdEncoding.DecodeString(request.Content)

		if err == nil {
			err = json.Unmarshal(c,&response)
			if err == nil{
				response.Verified = true
				return &response
			}
		}
	}

	return nil

}