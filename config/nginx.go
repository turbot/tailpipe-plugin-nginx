package config

import "github.com/turbot/tailpipe-plugin-sdk/parse"

type NginxConnection struct {
	// Optional common settings that affect all sources using this connection
	DefaultLogFormat  string `json:"default_log_format,omitempty" hcl:"default_log_format,optional"`
	DefaultTimezone   string `json:"default_timezone,omitempty" hcl:"default_timezone,optional"`
	DefaultServerName string `json:"default_server_name,omitempty" hcl:"default_server_name,optional"`
}

func NewNginxConnection() parse.Config {
	return &NginxConnection{
		// Set default values
		DefaultLogFormat:  "combined",
		DefaultTimezone:   "UTC",
		DefaultServerName: "default",
	}
}

func (c *NginxConnection) Validate() error {
	return nil
}