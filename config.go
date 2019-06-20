package venafi

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	
	"github.com/tradel/venafi-tpp/pkg/const/config"
)

type ConfigAttribute struct {
	Syntax   int
	Property int
	Name     string
}

type ConfigObject struct {
	AbsoluteGUID  string            `json:",omitempty"`
	AttributeList []ConfigAttribute `json:",omitempty"`
	DN            string            `json:",omitempty"`
	Id            int               `json:",omitempty"`
	GUID          string            `json:",omitempty"`
	Name          string            `json:",omitempty"`
	Parent        string            `json:",omitempty"`
	Revision      int64             `json:",omitempty"`
	Class         string            `json:"TypeName,omitempty"`
}

type ConfigService struct {
	client *Client
}

type ConfigCommonResult struct {
	Result config.ConfigResult
	Error  string
}

func (s *ConfigService) doRequestWithBody(method string, path string, body interface{}, output interface{}) (*http.Response, error) {

	res, err := s.client.doRequestWithBody(method, path, body)
	if err != nil {
		return nil, err
	}

	var save io.ReadCloser
	save, res.Body, err = drainBody(res.Body)
	if err != nil {
		return nil, err
	}

	var resultOutput ConfigCommonResult
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&resultOutput); err != nil {
		return nil, err
	}

	if resultOutput.Result != config.Success {
		return nil, &ConfigServiceError{Result: resultOutput.Result, Message: resultOutput.Error}
	}

	res.Body = save
	defer res.Body.Close()

	if output != nil {
		if err := json.NewDecoder(res.Body).Decode(output); err != nil {
			return nil, err
		}
	}

	return res, nil
}

func (s *ConfigService) Create(objectDN string, className string, attributes map[string]string) (*ConfigObject, error) {
	type NameAttributePair struct {
		Name  string
		Value string
	}
	type Input struct {
		Class             string
		ObjectDN          string
		NameAttributeList []NameAttributePair `json:",omitempty"`
	}

	type Output struct {
		Object ConfigObject
	}

	var input Input = Input{Class: className, ObjectDN: objectDN, NameAttributeList: nil}
	if attributes != nil {
		input.NameAttributeList = make([]NameAttributePair, 0)
		for k, v := range attributes {
			input.NameAttributeList = append(input.NameAttributeList, NameAttributePair{k, v})
		}
	}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/Config/Create", input, &output)
	if err != nil {
		return nil, err
	}

	return &output.Object, nil
}

func (s *ConfigService) IsValid(objectDN string, objectGUID string) (*ConfigObject, error) {
	type Input struct {
		ObjectDN   string `json:",omitempty"`
		ObjectGUID string `json:",omitempty"`
	}
	type Output struct {
		Object ConfigObject
	}

	var input Input = Input{objectDN, objectGUID}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/Config/IsValid", input, &output)
	if err != nil {
		return nil, err
	}

	return &output.Object, nil
}

func (s *ConfigService) Exists(objectDN string) bool {
	_, err := s.IsValid(objectDN, "")
	if err != nil {
		return false
	}
	return true
}

func (s *ConfigService) Retrieve(objectDN string) (*ConfigObject, error) {
	return s.IsValid(objectDN, "")
}

func (s *ConfigService) DefaultDN() (string, error) {
	type Output struct {
		DefaultDN string
	}

	var output Output

	_, err := s.doRequestWithBody("GET", "/vedsdk/Config/DefaultDn", nil, &output)
	if err != nil {
		return "", err
	}

	return output.DefaultDN, nil
}

func (s *ConfigService) Delete(objectDN string, recursive bool) error {
	type Input struct {
		ObjectDN  string
		Recursive int
	}

	var input Input = Input{ObjectDN: objectDN, Recursive: btoi(recursive)}

	_, err := s.doRequestWithBody("POST", "/vedsdk/Config/Delete", input, nil)
	if err != nil {
		return err
	}

	return nil
}

func (s *ConfigService) Enumerate(objectDN string, recursive bool, filter string) ([]ConfigObject, error) {
	type Input struct {
		ObjectDN  string
		Recursive string
		Pattern   string `json:",omitempty"`
	}
	type Output struct {
		Objects []ConfigObject
	}

	var input Input = Input{objectDN, strconv.FormatBool(recursive), filter}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/Config/Enumerate", input, &output)
	if err != nil {
		return nil, err
	}

	return output.Objects, nil

}

func (s *ConfigService) AddValue(objectDN string, name string, value string) error {
	type Input struct {
		ObjectDN      string
		AttributeName string
		Value         string
	}

	var input Input = Input{objectDN, name, value}

	_, err := s.doRequestWithBody("POST", "/vedsdk/Config/AddValue", input, nil)
	if err != nil {
		return err
	}

	return nil
}

func (s *ConfigService) ClearAttribute(objectDN string, name string) error {
	type Input struct {
		ObjectDN      string
		AttributeName string
	}

	var input Input = Input{objectDN, name}

	_, err := s.doRequestWithBody("POST", "/vedsdk/Config/ClearAttribute", input, nil)
	if err != nil {
		return err
	}

	return nil
}

func (s *ConfigService) Read(objectDN string, name string) ([]string, error) {
	type Input struct {
		ObjectDN      string
		AttributeName string
	}

	type Output struct {
		ObjectDN      string
		AttribtueName string
		Values        []string
	}

	var input Input = Input{objectDN, name}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/Config/Read", input, &output)
	if err != nil {
		return nil, err
	}

	return output.Values, nil
}

func (s *ConfigService) ReadAll(objectDN string) (map[string][]string, error) {
	type Input struct {
		ObjectDN string
	}
	type NameValuePair struct {
		Name   string
		Values []string
	}
	type Output struct {
		NameValues []NameValuePair
	}

	var input Input = Input{objectDN}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/Config/ReadAll", input, &output)
	if err != nil {
		return nil, err
	}

	rv := make(map[string][]string)
	for _, pair := range output.NameValues {
		rv[pair.Name] = pair.Values
	}

	return rv, nil
}

func (s *ConfigService) Write(objectDN string, attributes map[string][]string) error {
	type NameAttributePair struct {
		Name  string
		Value []string
	}
	type Input struct {
		ObjectDN      string
		AttributeData []NameAttributePair
	}

	var input Input = Input{ObjectDN: objectDN, AttributeData: nil}
	if attributes != nil {
		input.AttributeData = make([]NameAttributePair, 0)
		for k, v := range attributes {
			input.AttributeData = append(input.AttributeData, NameAttributePair{k, v})
		}
	}

	_, err := s.doRequestWithBody("POST", "/vedsdk/Config/Write", input, nil)
	if err != nil {
		return err
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Helper funcs
///////////////////////////////////////////////////////////////////////////////

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// drainBody reads all of b to memory and then returns two equivalent
// ReadClosers yielding the same bytes.
//
// It returns an error if the initial slurp of all bytes fails. It does not attempt
// to make the returned ReadClosers have identical error-matching behavior.
func drainBody(b io.ReadCloser) (r1, r2 io.ReadCloser, err error) {
	if b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return http.NoBody, http.NoBody, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, b, err
	}
	if err = b.Close(); err != nil {
		return nil, b, err
	}
	return ioutil.NopCloser(&buf), ioutil.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

///////////////////////////////////////////////////////////////////////////////
// Errors
///////////////////////////////////////////////////////////////////////////////

type ConfigServiceError struct {
	Result  config.ConfigResult
	Message string
}

func (e *ConfigServiceError) Error() string {
	return e.Message
}
