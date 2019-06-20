package venafi

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/tradel/venafi-tpp/pkg/const/secret_store"
	"github.com/tradel/venafi-tpp/pkg/pem"
)

type X509StoreService struct {
	client *Client
}

func (s *X509StoreService) doRequestWithBody(method string, path string, body interface{}, output interface{}) (*http.Response, error) {

	res, err := s.client.doRequestWithBody(method, path, body)
	if err != nil {
		return nil, err
	}

	var save io.ReadCloser
	save, res.Body, err = drainBody(res.Body)
	if err != nil {
		return nil, err
	}

	var resultOutput struct {
		Result secret_store.SecretStoreResult
	}

	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&resultOutput); err != nil {
		return nil, err
	}

	if resultOutput.Result != secret_store.Success {
		return nil, &X509StoreServiceError{Result: resultOutput.Result}
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

func (s *X509StoreService) Add(cert *x509.Certificate, ownerDN string, protectionKey string) (int, error) {
	certText, err := pem.EncodeCert(cert)
	if err != nil {
		return -1, err
	}

	b64 := base64.StdEncoding.EncodeToString([]byte(certText))

	type Input struct {
		CertificateString string
		OwnerDN           string
		ProtectionKey     string
	}
	type Output struct {
		Result  secret_store.SecretStoreResult
		VaultId int
	}

	var input Input = Input{b64, ownerDN, protectionKey}
	var output Output

	_, err = s.doRequestWithBody("POST", "/vedsdk/X509CertificateStore/Add", input, &output)
	if err != nil {
		return -1, err
	}

	return output.VaultId, nil
}

func (s *X509StoreService) Lookup(cert *x509.Certificate, ownerDN string, name string, value string) ([]int, error) {
	b64 := ""
	if cert != nil {
		certText, err := pem.EncodeCert(cert)
		if err != nil {
			return nil, err
		}
		b64 = base64.StdEncoding.EncodeToString([]byte(certText))
	}

	type Input struct {
		CertificateString string `json:",omitempty"`
		OwnerDN           string `json:",omitempty"`
		Name              string `json:",omitempty"`
		Value             string `json:",omitempty"`
	}
	type Output struct {
		VaultIds []int
		Result   secret_store.SecretStoreResult
	}

	var input Input = Input{b64, ownerDN, name, value}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/X509CertificateStore/Lookup", input, &output)
	if err != nil {
		return nil, err
	}

	return output.VaultIds, nil
}

func (s *X509StoreService) LookupByCertificate(cert *x509.Certificate) ([]int, error) {
	return s.Lookup(cert, "", "", "")
}

func (s *X509StoreService) LookupByOwnerDN(ownerDN string) ([]int, error) {
	return s.Lookup(nil, ownerDN, "", "")
}

func (s *X509StoreService) LookupByNameValue(name string, value string) ([]int, error) {
	return s.Lookup(nil, "", name, value)
}

func (s *X509StoreService) LookupExpiring(days int, ownerDN string) ([]int, error) {
	type Input struct {
		DaysToExpiration int
		OwnerDN          string
	}
	type Output struct {
		VaultIds []int
		Result   secret_store.SecretStoreResult
	}

	var input Input = Input{days, ownerDN}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/X509CertificateStore/LookupExpiring", input, &output)
	if err != nil {
		return nil, err
	}

	return output.VaultIds, nil
}

func (s *X509StoreService) Retrieve(vaultID int) (*x509.Certificate, error) {
	type Input struct {
		VaultId int
	}
	type Output struct {
		CertificateString string
		Result            secret_store.SecretStoreResult
	}

	var input Input = Input{vaultID}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/X509CertificateStore/Retrieve", input, &output)
	if err != nil {
		return nil, err
	}

	certBytes, err := base64.StdEncoding.DecodeString(output.CertificateString)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}

func (s *X509StoreService) Remove(vaultID int, ownerDN string) error {
	type Input struct {
		VaultId int
		OwnerDN string
	}
	type Output struct {
		Result secret_store.SecretStoreResult
	}

	var input Input = Input{vaultID, ownerDN}
	var output Output

	_, err := s.doRequestWithBody("POST", "/vedsdk/X509CertificateStore/Remove", input, &output)
	if err != nil {
		return err
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Errors
///////////////////////////////////////////////////////////////////////////////

type X509StoreServiceError struct {
	Result secret_store.SecretStoreResult
}

func (e *X509StoreServiceError) Error() string {
	return e.Message()
}

func (e *X509StoreServiceError) Message() string {
	return e.Result.String()
}
