package venafi

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/tradel/venafi-tpp/pkg/pem"
)

type CertificateService struct {
	client *Client
}

type X509Data struct {
	CommonName string              `json:"CN"`
	AltNames   map[string][]string `json:"SANS"`
	Serial     string
	Thumbprint string
	ValidFrom  time.Time
	ValidTo    time.Time
}

type Certificate struct {
	CreatedOn  time.Time
	ObjectDN   string `json:"DN"`
	ObjectGUID string `json:"Guid"`
	Name       string
	ParentDN   string `json:"ParentDn"`
	Class      string `json:"SchemaClass"`
	X509       X509Data
}

type CertificateServiceError struct {
	Message string `json:"Error"`
}

func (e *CertificateServiceError) Error() string {
	return e.Message
}


func (s *CertificateService) doRequestWithBody(method string, path string, params interface{}, output interface{}) (*http.Response, error) {

	res, err := s.client.doRequestWithBody(method, path, params)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	if res.StatusCode == 400 {
		var errorOutput CertificateServiceError
		if err := json.NewDecoder(res.Body).Decode(&errorOutput); err != nil {
			return nil, err
		}
		return nil, &errorOutput
	}

	if output != nil {
		if err := json.NewDecoder(res.Body).Decode(output); err != nil {
			return nil, err
		}
	}

	return res, nil
}

func (s *CertificateService) List() ([]Certificate, error) {
	type Output struct {
		Certificates []Certificate
		DataRange    string
		TotalCount   int
		Links        []map[string]string `json:"_links,omitempty"`
	}

	results := make([]Certificate, 0)
	offset := 0
	limit := 100
	for {
		params := map[string]string{
			"limit":  strconv.Itoa(limit),
			"offset": strconv.Itoa(offset),
		}
		var output Output
		_, err := s.client.doJsonRequestWithParams("GET", "/vedsdk/certificates/", params, &output)
		if err != nil {
			return nil, err
		}

		for _, cert := range output.Certificates {
			results = append(results, cert)
		}

		if output.Links == nil {
			break
		}

		offset += limit
	}

	return results, nil
}

func (s *CertificateService) Retrieve(certDN string) (*x509.Certificate, crypto.Signer, error) {
	type Input struct {
		CertificateDN     string
		Format            string
		IncludeChain      bool
		IncludePrivateKey bool
		Password          string
	}
	type Output struct {
		CertificateData string
		Filename        string
		Format          string
	}

	var input Input = Input{certDN, "Base64", false, true, "Passw0rd"}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/certificates/Retrieve", input, &output)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := base64.StdEncoding.DecodeString(output.CertificateData)
	if err != nil {
		return nil, nil, err
	}

	return pem.DecodeCertAndPrivateKey(certBytes, "Passw0rd")
}

type ImportCertificateOutput struct {
	CertificateDN      string
	CertificateVaultId int
	CertificateGuid    string `json:"Guid"`
	PrivateKeyVaultId  int
}

func (s *CertificateService) Import(parentDN string, objectName string, cert *x509.Certificate, pk crypto.Signer, reconcile bool) (*ImportCertificateOutput, error) {
	type Input struct {
		PolicyDN        string
		ObjectName      string
		CertificateData string
		Password        string `json:",omitempty"`
		PrivateKeyData  string `json:",omitempty"`
		Reconcile       bool
	}

	certPEM, err := pem.EncodeCert(cert)
	if err != nil {
		return nil, err
	}

	keyPEM, err := pem.EncodeKey(pk, "Passw0rd", x509.PEMCipher3DES)

	var input Input = Input{parentDN, objectName, certPEM, "Passw0rd", keyPEM, reconcile}
	var output ImportCertificateOutput

	_, err = s.doRequestWithBody("POST", "/vedsdk/certificates/Import", input, &output)
	if err != nil {
		return nil, err
	}

	return &output, nil

}
