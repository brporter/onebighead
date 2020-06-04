package utility

import (
	_ "fmt"
	"io/ioutil"
	"net/http"
)

type HttpClient interface {
	Get(url string) ([]byte, error)
}

type HttpClientGeneratorFunc func() HttpClient

var HttpClientGenerator HttpClientGeneratorFunc = func() HttpClient {
	return &systemHttpClient{}
}

func NewHttpClient() HttpClient {
	return HttpClientGenerator()
}

type systemHttpClient struct {
}

func HttpGet(url string) ([]byte, error) {
	client := NewHttpClient()
	return client.Get(url)
}

func (*systemHttpClient) Get(url string) ([]byte, error) {
	resp, err := http.Get(url)

	if err != nil {
		return nil, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}
