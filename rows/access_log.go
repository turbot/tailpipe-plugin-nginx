package rows

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
)

type AccessLog struct {
    enrichment.CommonFields

    RemoteAddr    *string    `json:"remote_addr,omitempty"`
    RemoteUser    *string    `json:"remote_user,omitempty"`
    TimeLocal     *string    `json:"time_local,omitempty"`
    TimeIso8601   *string    `json:"time_iso_8601,omitempty"`
    Request       *string    `json:"request,omitempty"`
    Method        *string    `json:"method,omitempty"`
    Path          *string    `json:"path,omitempty"`
    HttpVersion   *string    `json:"http_version,omitempty"`
    Status        *int       `json:"status,omitempty"`
    BodyBytesSent *int       `json:"body_bytes_sent,omitempty"`
    HttpReferer   *string    `json:"http_referer,omitempty"`
    HttpUserAgent *string    `json:"http_user_agent,omitempty"`
    Timestamp     *time.Time `json:"timestamp,omitempty"`
}

func NewAccessLog() *AccessLog {
	return &AccessLog{}
}

func (l *AccessLog) InitialiseFromMap(m map[string]string) error {
	for key, value := range m {
		switch key {
		case "remote_addr":
			l.RemoteAddr = &value
			l.TpSourceIP = &value
			l.TpIps = append(l.TpIps, value)
		case "remote_user":
			l.RemoteUser = &value
			if value != "" && value != "-" {
				l.TpUsernames = append(l.TpUsernames, value)
			}
		case "time_local":
			l.TimeLocal = &value
			t, err := time.Parse("02/Jan/2006:15:04:05 -0700", value)
			if err != nil {
				return err
			}
			iso := t.Format(time.RFC3339)
			l.TimeIso8601 = &iso
			l.Timestamp = &t
		case "time_iso8601":
			l.TimeIso8601 = &value
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return err
			}
			l.Timestamp = &t
		case "body_bytes_sent":
			bbs, err := strconv.Atoi(value)
			if err != nil {
				return err
			}
			l.BodyBytesSent = &bbs
		case "http_referer":
			l.HttpReferer = &value
		case "http_user_agent":
			l.HttpUserAgent = &value
		case "request":
			l.Request = &value
			// Split "GET /login HTTP/1.1" into components
			parts := strings.SplitN(value, " ", 3)
			if len(parts) == 3 {
				method := parts[0]
				path := parts[1]
				version := strings.TrimPrefix(parts[2], "HTTP/")
				l.Method = &method
				l.Path = &path
				l.HttpVersion = &version

				// While we're here, let's add some enrichment
				// Add method tag
				l.TpTags = append(l.TpTags, "method:"+method)
				// Add status-based tags in the status case below

				// Extract domain from path if it looks like a full URL
				if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
					if u, err := url.Parse(path); err == nil && u.Hostname() != "" {
						l.TpDomains = append(l.TpDomains, u.Hostname())
					}
				}

				// Add path to AKAs
				l.TpAkas = append(l.TpAkas, path)
			}
		case "status":
			status, err := strconv.Atoi(value)
			if err != nil {
				return err
			}
			l.Status = &status
			// Add status-based tags
			if status >= 400 {
				l.TpTags = append(l.TpTags, "error")
				if status >= 500 {
					l.TpTags = append(l.TpTags, "server_error")
				} else {
					l.TpTags = append(l.TpTags, "client_error")
				}
			}		
		}
	}
	return nil
}
