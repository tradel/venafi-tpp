package venafi

import (
	"strconv"
	"venafi-tpp/pkg/const/ca"
	"venafi-tpp/pkg/const/config"
)

type CAService struct {
	client *Client
}

func (s *CAService) Create(objectDN string, className string, driverName string,
	extraProperties map[string]string) (*ConfigObject, error) {
	me, err := s.client.Identity.Self()
	if err != nil {
		return nil, err
	}

	allProps := map[string]string{
		"Contact":     me.PrefixedUniversal,
		"Driver Name": driverName,
	}

	if extraProperties != nil {
		for k, v := range extraProperties {
			allProps[k] = v
		}
	}

	obj, err := s.client.Config.Create(objectDN, className, allProps)
	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (s *CAService) CreateSelfSigned(objectDN string, keyUsage ca.KeyUsage, signingAlgorithm string, sanEnabled bool, validityDays int) (*ConfigObject, error) {
	if signingAlgorithm == "" {
		signingAlgorithm = ca.AlgorithmSHA256
	}

	return s.Create(objectDN, config.ClassSelfSignedCA, config.DriverSelfSigned, map[string]string{
		"Algorithm":       signingAlgorithm,
		"Key Usage":       keyUsage.String(),
		"Validity Period": strconv.Itoa(validityDays),
		"SAN Enabled":     strconv.Itoa(btoi(sanEnabled)),
	})
}

func (s *CAService) CreateOpenSSL(objectDN string, hostname string, sshKeyDN string, sshPort int,
	caConfigFilePath string, caCertDir string, caRootCertFile string, caPrivateKeyFile string, certPrivateKeyDN string,
	tempDir string, sanEnabled bool, copyExtensions bool, maxValidityYears int) (*ConfigObject, error) {
	extraProps := map[string]string{
		"Certificate Directory":           caCertDir,
		"Certificate File":                caRootCertFile,
		"Configuration File":              caConfigFilePath,
		"Credential":                      sshKeyDN,
		"Host":                            hostname,
		"Private Key File":                caPrivateKeyFile,
		"Private Key Password Credential": certPrivateKeyDN,
		"SAN Enabled":                     strconv.Itoa(btoi(sanEnabled)),
		"Temp Directory":                  tempDir,
	}
	if copyExtensions {
		extraProps["Copy Extensions"] = "copy"
	}

	obj, err := s.Create(objectDN, config.ClassOpenSSLCA, config.DriverOpenSSL, extraProps)
	if err != nil {
		return nil, err
	}

	periods := make([]string, 0)
	for i := 1; i <= maxValidityYears; i++ {
		periods = append(periods, strconv.Itoa(i))
	}
	err = s.client.Config.Write(objectDN, map[string][]string{
		"Validity Period": periods,
	})
	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (s *CAService) Delete(objectDN string, recursive bool) error {
	return s.client.Config.Delete(objectDN, recursive)
}
