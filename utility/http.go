package utility

import (
	"io/ioutil"
	"net/http"
)

// HTTPClient defines the interface of types capable of executing HTTP requests
type HTTPClient interface {
	Get(url string) ([]byte, error)
}

// HTTPClientGeneratorFunc is a function capable of return an implementation of the HTTPClient interface
type HTTPClientGeneratorFunc func() HTTPClient

// HTTPClientGenerator is a function that is capable of generating an new HTTPClient
var HTTPClientGenerator HTTPClientGeneratorFunc = func() HTTPClient {
	return &systemHTTPClient{}
}

// NewHTTPClient creates a new HTTPClient
func NewHTTPClient() HTTPClient {
	return HTTPClientGenerator()
}

type systemHTTPClient struct {
}

// HTTPGet retrieves the document at the specified url and returns the bytes of the body of the document, if successful
func HTTPGet(url string) ([]byte, error) {
	client := NewHTTPClient()
	return client.Get(url)
}

// Get retrieves the document at the specified url and returns the bytes of the body of the document, if successful
func (*systemHTTPClient) Get(url string) ([]byte, error) {
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
