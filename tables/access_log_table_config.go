package tables

import "fmt"

type AccessLogTableConfig struct {
	LogFormat *string `hcl:"log_format"`
}

func (a *AccessLogTableConfig) Validate() error {
	if a.LogFormat != nil && *a.LogFormat == "" {
		return fmt.Errorf("log_format cannot be empty")
	}

	return nil
}
