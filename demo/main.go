package main

import (
	"fmt"
	"time"
	"github.com/dreamsxin/paynicorn-sdk-golang"
	"github.com/gin-gonic/gin"
	"net/http"
)

var appkey = "xxxx"
var merchantkey = "xxxxx"

func main() {
    res, _ := paynicorn.GetPaynicornAccessToken(appkey,merchantkey,"t4k8OxpNz53vhPJV")
    if res != nil{
		fmt.Println(res)
	}
    res2, _ := paynicorn.GetPaynicornUserinfo(appkey, merchantkey,"t4k8OxpNz53vhPJV")
    if res2 != nil{
		fmt.Println(res2)
	}
}

func testhttp() {
	//raise a payment request to PAYNICORN
	request := paynicorn.InitPaymentRequest{}
	request.OrderId="testorder" + time.Now().Format("2006-01-02 15:04:05")
	request.CountryCode="NG"
	request.Currency="NGN"
	request.Amount="10"
	request.CpFrontPage="http://localhost/pay/result"
	request.OrderDescription="TEST GOODS NAME"
	response := paynicorn.InitPayment(appkey,merchantkey,request)
	if response != nil{
		fmt.Println(response)
	}

	//query a payment status from PAYNICORN
	request1 := paynicorn.QueryPaymentRequest{}
	request1.OrderId=request.OrderId
	request1.TxnType=paynicorn.PAYMENT
	response1 := paynicorn.QueryPayment(appkey,merchantkey,request1)
	if response1 != nil{
		fmt.Println(response1)
	}


	//query support payment method from PAYNICORN
	request2 := paynicorn.QueryMethodRequest{}
	request2.TxnType = paynicorn.PAYMENT
	request2.CountryCode = "NG"
	request2.Currency = "NGN"
	response2 := paynicorn.QueryMethod(appkey,merchantkey,request2)
	if response2 != nil{
		fmt.Println(response2)
	}


	//receive a payment status postback from PAYNICORN
	r := gin.Default()
	r.POST("/postback", func(context *gin.Context) {

		var req paynicorn.PostbackRequest
		if err := context.BindJSON(&req); err != nil{
			context.String(http.StatusInternalServerError,"")
		}else{
			postbackInfo := paynicorn.ReceivePostback(merchantkey,req)
			if postbackInfo != nil && postbackInfo.Verified{
				fmt.Println(postbackInfo)
				context.String(http.StatusOK,"success_"+postbackInfo.TxnId)
			}else{
				context.String(http.StatusInternalServerError,"")
			}
		}

	})
	r.Run(":8080")


}
