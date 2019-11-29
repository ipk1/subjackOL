package subjack

import (
	"crypto/tls"
	"github.com/valyala/fasthttp"
	"time"
)

func get(url string, ssl bool, timeout int) (response *fasthttp.Response) {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(site(url, ssl))
	req.Header.Add("Connection", "close")
	resp := fasthttp.AcquireResponse()

	client := &fasthttp.Client{TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	client.DoTimeout(req, resp, time.Duration(timeout)*time.Second)

	//fmt.Println(url,resp.StatusCode())
	//fmt.Println(url, string(resp.Header.Header()))

	return resp
	//also return headers here..
	//also return response status code here ...
	// or return entire response object

}

func https(url string, ssl bool, timeout int) (response *fasthttp.Response) {
	newUrl := "https://" + url
	response = get(newUrl, ssl, timeout)

	return response
}

func site(url string, ssl bool) (site string) {
	site = "http://" + url
	if ssl {
		site = "https://" + url
	}

	return site
}
