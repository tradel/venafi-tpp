package ca

import "strings"

//noinspection GoUnusedConst
const (
	AlgorithmSHA1   = "SHA1"
	AlgorithmSHA256 = "SHA256"
)

type KeyUsage int

//noinspection GoUnusedConst
const (
	KeyUsageKeyAgreement KeyUsage = 1 << iota
	KeyUsageDataEncipherment
	KeyUsageKeyEncipherment
	KeyUsageDigitalSignature
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
	KeyUsageNonRepudiation
)

func (k KeyUsage) String() string {
	var words []string = make([]string, 0)
	if k&KeyUsageKeyAgreement != 0 {
		words = append(words, "KeyAgreement")
	}
	if k&KeyUsageDataEncipherment != 0 {
		words = append(words, "DataEncipherment")
	}
	if k&KeyUsageKeyEncipherment != 0 {
		words = append(words, "KeyEncipherment")
	}
	if k&KeyUsageDigitalSignature != 0 {
		words = append(words, "DigitalSignature")
	}
	if k&KeyUsageEncipherOnly != 0 {
		words = append(words, "EncipherOnly")
	}
	if k&KeyUsageDecipherOnly != 0 {
		words = append(words, "DecipherOnly")
	}
	if k&KeyUsageNonRepudiation != 0 {
		words = append(words, "NonRepudiation")
	}
	return strings.Join(words, ", ")
}
