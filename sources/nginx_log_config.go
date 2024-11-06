package sources

import (
	"fmt"
	"time"
	"github.com/hashicorp/hcl/v2"
)

type AccessLogFileSourceConfig struct {
	// required to allow partial decoding
	Remain hcl.Body `hcl:",remain" json:"-"`

	// Path to NGINX access log file or directory
	LogPath string `json:"log_path" hcl:"log_path"`
	
	// Optional: Pattern for log files if LogPath is a directory
	FilePattern string `json:"file_pattern,omitempty" hcl:"file_pattern,optional"`
	
	// Optional: Log format if not using combined format
	LogFormat string `json:"log_format,omitempty" hcl:"log_format,optional"`

	// Optional: Location values for better data organization
	Location    string `json:"location,omitempty" hcl:"location,optional"`
	ServerName  string `json:"server_name,omitempty" hcl:"server_name,optional"`
	
	// Optional: Parse timezone for log entries
	Timezone string `json:"timezone,omitempty" hcl:"timezone,optional"`
}

func (c *AccessLogFileSourceConfig) Validate() error {
	if c.LogPath == "" {
		return fmt.Errorf("log_path is required")
	}

	// Optional timezone validation
	if c.Timezone != "" {
		_, err := time.LoadLocation(c.Timezone)
		if err != nil {
			return fmt.Errorf("invalid timezone: %v", err)
		}
	}

	return nil
}