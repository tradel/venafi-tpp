package venafi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/hashicorp/go-hclog"
)

type Client struct {
	Username  string
	Password  string
	BaseURL   *url.URL
	APIKey    string
	client    *http.Client
	X509Store *X509StoreService
	Identity  *IdentityService
	Config    *ConfigService
	Policy    *PolicyService
	CA        *CAService
	Certs     *CertificateService
	logger    hclog.Logger
}

func NewClient(httpAddress string, username string, password string, httpClient *http.Client) (*Client, error) {
	baseURL, err := url.Parse(httpAddress)
	if err != nil {
		return nil, fmt.Errorf("error parsing Venafi base URL: %s", err)
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	c := &Client{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		client:   httpClient,
		logger: hclog.New(&hclog.LoggerOptions{
			Name:  "venafi",
			Level: hclog.Debug,
		}),
	}

	c.X509Store = &X509StoreService{c}
	c.Identity = &IdentityService{c}
	c.Config = &ConfigService{c}
	c.Policy = &PolicyService{c}
	c.CA = &CAService{c}
	c.Certs = &CertificateService{c}

	return c, nil
}

func NewFromEnviron() (*Client, error) {
	return NewClient(os.Getenv("VENAFI_TPP_ADDR"),
		os.Getenv("VENAFI_TPP_USERNAME"),
		os.Getenv("VENAFI_TPP_PASSWORD"),
		nil)
}

func (c *Client) getURL(path string) (*url.URL, error) {
	uri, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL path: %s", err)
	}

	combined := c.BaseURL.ResolveReference(uri)
	return combined, nil
}

func (c *Client) prepareRequest(method string, url *url.URL, params map[string]string, body interface{}) (*http.Request, error) {
	var buf io.ReadWriter //= new(bytes.Buffer)
	if body != nil {
		//buf2 := new(bytes.Buffer)
		buf = new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return nil, err
		}
		//buf = buf2
	}

	if params != nil {
		q := url.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		url.RawQuery = q.Encode()
	}

	req, err := http.NewRequest(method, url.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	if c.APIKey != "" {
		req.Header.Set("X-Venafi-Api-Key", c.APIKey)
	}

	req.Header.Set("Accept", "application/json")

	return req, nil
}

func (c *Client) doRequestInternal(method string, url *url.URL, params map[string]string, body interface{}) (*http.Response, error) {
	req, err := c.prepareRequest(method, url, params, body)
	if err != nil {
		return nil, err
	}

	reqText, _ := httputil.DumpRequest(req, true)
	c.logger.Debug("Sending request:\n" + string(reqText))

	res, err := c.client.Do(req)
	if err != nil {
		return res, err
	}

	resText, _ := httputil.DumpResponse(res, true)
	c.logger.Debug("Received response:\n" + string(resText))

	if res.StatusCode > 400 {
		return res, fmt.Errorf("unexpected status code response: %d (%s)", res.StatusCode, res.Status)
	}

	return res, nil
}

func (c *Client) doRequestWithParams(method string, path string, params map[string]string) (*http.Response, error) {
	if c.APIKey == "" {
		if err := c.getAPIKey(); err != nil {
			return nil, err
		}
	}

	finalUrl, err := c.getURL(path)
	if err != nil {
		return nil, err
	}

	return c.doRequestInternal(method, finalUrl, params, nil)
}

func (c *Client) doJsonRequestWithParams(method string, path string, params map[string]string, output interface{}) (*http.Response, error) {
	res, err := c.doRequestWithParams(method, path, params)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&output); err != nil {
		return nil, err
	}

	return res, nil
}

func (c *Client) doRequestWithBody(method string, path string, body interface{}) (*http.Response, error) {
	if c.APIKey == "" {
		if err := c.getAPIKey(); err != nil {
			return nil, err
		}
	}

	finalUrl, err := c.getURL(path)
	if err != nil {
		return nil, err
	}

	return c.doRequestInternal(method, finalUrl, nil, body)
}

func (c *Client) doJsonRequestWithBody(method string, path string, body interface{}, output interface{}) (*http.Response, error) {
	res, err := c.doRequestWithBody(method, path, body)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&output); err != nil {
		return nil, err
	}

	return res, nil
}

func (c *Client) getAPIKey() error {
	c.APIKey = ""

	finalUrl, err := c.getURL("/vedsdk/authorize/")
	if err != nil {
		return err
	}

	req, err := c.prepareRequest("POST", finalUrl, nil, map[string]interface{}{
		"Username": c.Username,
		"Password": c.Password,
	})

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}

	e := make(map[string]string)

	if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
		return err
	}

	if err := res.Body.Close(); err != nil {
		return err
	}
	c.APIKey = e["APIKey"]

	return nil
}
