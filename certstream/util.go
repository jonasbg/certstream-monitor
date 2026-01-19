package certstream

import (
	"encoding/json"
	"os"
)

// GetCertificateFromFile loads a certificate from a JSON file
func GetCertificateFromFile(path string) (*CertData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cert CertData
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, err
	}

	return &cert, nil
}
