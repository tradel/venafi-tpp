package venafi

import (
	"fmt"
)

type IdentityService struct {
	client *Client
}

type Identity struct {
	FullName          string  `json:",omitempty"`
	IsContainer       bool    `json:",omitempty"`
	IsGroup           bool    `json:",omitempty"`
	Name              string  `json:",omitempty"`
	Prefix            string  `json:",omitempty"`
	PrefixedName      string  `json:",omitempty"`
	PrefixedUniversal string  `json:",omitempty"`
	Universal         string  `json:",omitempty"`
}

func (s *IdentityService) Self() (*Identity, error) {
	type Output struct {
		Identities []Identity
	}

	var output Output

	_, err := s.client.doJsonRequestWithBody("GET", "/vedsdk/Identity/Self", nil, &output)
	if err != nil {
		return nil, err
	}

	for _, identity := range output.Identities {
		if identity.Name == s.client.Username {
			return &identity, nil
		}
	}

	return nil, fmt.Errorf("username not found in identity output: %s", s.client.Username)
}

func (s *IdentityService) Validate(id *Identity) (*Identity, error) {
	type Input struct {
		ID Identity
	}
	type Output struct {
		ID Identity
	}

	var input Input = Input{*id}
	var output Output

	_, err := s.client.doJsonRequestWithBody("POST", "/vedsdk/Identity/Validate", input, &output)
	if err != nil {
		return nil, err
	}

	return &output.ID, nil
}