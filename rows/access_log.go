package rows

import (
	"strconv"
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
)

type AccessLog struct {
	enrichment.CommonFields

	RemoteAddr    *string    `json:"remote_addr,omitempty"`
	RemoteUser    *string    `json:"remote_user,omitempty"`
	TimeLocal     *string    `json:"time_local,omitempty"`
	TimeIso8601   *string    `json:"time_iso8601,omitempty"`
	Request       *string    `json:"request,omitempty"`
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
		case "request":
			l.Request = &value
		case "status":
			status, err := strconv.Atoi(value)
			if err != nil {
				return err
			}
			l.Status = &status
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
		}
	}
	return nil
}
