package sources

import (
	"fmt"
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
}

func (c *AccessLogFileSourceConfig) Validate() error {
	if c.LogPath == "" {
		return fmt.Errorf("log_path is required")
	}
	return nil
}