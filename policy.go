package venafi

import "venafi-tpp/pkg/const/config"

type PolicyService struct {
	client *Client
}

func (s *PolicyService) Create(objectDN string) (*ConfigObject, error) {
	me, err := s.client.Identity.Self()
	if err != nil {
		return nil, err
	}

	obj, err := s.client.Config.Create(objectDN, config.ClassPolicy, map[string]string{
		"Contact": me.PrefixedUniversal,
	})
	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (s *PolicyService) Delete(objectDN string, recursive bool) error {
	return s.client.Config.Delete(objectDN, recursive)
}

func (s *PolicyService) Exists(objectDN string) bool {
	return s.client.Config.Exists(objectDN)
}
