package pem

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	pemlib "encoding/pem"
	"fmt"
)

const (
	RSAKeyBlockType      = "RSA PRIVATE KEY"
	ECDSAKeyBlockType    = "ECDSA PRIVATE KEY"
	PKCS8KeyBlockType    = "PRIVATE KEY"
	CertificateBlockType = "CERTIFICATE"
)

func EncodeCert(cert *x509.Certificate) (string, error) {
	var pemBuf bytes.Buffer
	err := pemlib.Encode(&pemBuf, &pemlib.Block{Type: CertificateBlockType, Bytes: cert.Raw})
	if err != nil {
		return "", err
	}
	return pemBuf.String(), nil
}

func EncodeKey(pk crypto.Signer, password string, cipher x509.PEMCipher) (string, error) {
	var pkBytes []byte
	var pemType string
	var err error
	switch pk.(type) {
	case *rsa.PrivateKey:
		pkBytes = x509.MarshalPKCS1PrivateKey(pk.(*rsa.PrivateKey))
		pemType = RSAKeyBlockType
	case *ecdsa.PrivateKey:
		pkBytes, err = x509.MarshalECPrivateKey(pk.(*ecdsa.PrivateKey))
		if err != nil {
			return "", err
		}
		pemType = ECDSAKeyBlockType
	default:
		return "", fmt.Errorf("unknown private key type")
	}

	pemBlock, err := x509.EncryptPEMBlock(rand.Reader, pemType, pkBytes, []byte(password), cipher)
	if err != nil {
		return "", err
	}

	var pemBuf bytes.Buffer
	err = pemlib.Encode(&pemBuf, pemBlock)
	return pemBuf.String(), err
}

func internalDecodeBlock(pemBytes []byte) (*pemlib.Block, []byte, error) {
	block, remainder := pemlib.Decode(pemBytes)
	if block == nil {
		return nil, remainder, fmt.Errorf("no PEM-encoded data found")
	}
	return block, remainder, nil
}

func internalParseCert(block *pemlib.Block) (*x509.Certificate, error) {
	if block.Type != CertificateBlockType {
		return nil, fmt.Errorf("expecting a block of type %s, got %s", CertificateBlockType, block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func internalParseKey(block *pemlib.Block) (crypto.Signer, error) {
	switch block.Type {
	case RSAKeyBlockType:
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case ECDSAKeyBlockType:
		return x509.ParseECPrivateKey(block.Bytes)
	case PKCS8KeyBlockType:
		signer, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := signer.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key is not a valid format")
		}
		return key, err
	default:
		return nil, fmt.Errorf("unknown private key type: %s", block.Type)
	}
}

func DecodeCertString(certText string) (*x509.Certificate, error) {
	block, _, err := internalDecodeBlock([]byte(certText))
	if err != nil {
		return nil, err
	}
	cert, err := internalParseCert(block)
	return cert, err
}

func DecodePrivateKey(keyText string) (crypto.Signer, error) {
	block, _, err := internalDecodeBlock([]byte(keyText))
	if err != nil {
		return nil, err
	}
	key, err := internalParseKey(block)
	return key, err
}

func DecodeCertAndPrivateKey(certBytes []byte, password string) (*x509.Certificate, crypto.Signer, error) {
	block, remainder, err := internalDecodeBlock(certBytes)
	if err != nil {
		return nil, nil, err
	}
	cert, err := internalParseCert(block)
	if err != nil {
		return nil, nil, err
	}

	block, _, err = internalDecodeBlock(remainder)
	if err != nil {
		return nil, nil, err
	}

	if password != "" {
		block.Bytes, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, nil, fmt.Errorf("error decrypting PEM block")
		}
	}

	pk, err := internalParseKey(block)
	if err != nil {
		return nil, nil, err
	}

	return cert, pk, nil
}
