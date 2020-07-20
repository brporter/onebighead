package utility

import (
	"io/ioutil"
	"net/http"
)

// HTTPClient defines the interface of types capable of executing HTTP requests
type HTTPClient interface {
	Get(url string) ([]byte, error)
}

// NewHTTPClient creates a new HTTPClient
func NewHTTPClient() HTTPClient {
	return &systemHTTPClient{}
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
