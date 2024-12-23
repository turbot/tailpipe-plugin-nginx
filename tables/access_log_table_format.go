package tables

import "fmt"

type AccessLogTableFormat struct {
	LogFormat *string `hcl:"log_format"`
}

func (a *AccessLogTableFormat) Validate() error {
	if a.LogFormat != nil && *a.LogFormat == "" {
		return fmt.Errorf("log_format cannot be empty")
	}

	return nil
}

func (a *AccessLogTableFormat) Identifier() string {
	return AccessLogTableIdentifier
}
