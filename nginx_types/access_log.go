package nginx_types

import (
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
)

type AccessLog struct {
	enrichment.CommonFields
	RawAccessLog
	Timestamp time.Time `json:"timestamp"`
}

type RawAccessLog struct {
	RemoteAddr    string `json:"remote_addr"`
	RemoteUser    string `json:"remote_user"`
	TimeLocal     string `json:"time_local"`
	Request       string `json:"request"`
	Status        int    `json:"status"`
	BodyBytesSent int    `json:"body_bytes_sent"`
	HttpReferer   string `json:"http_referer"`
	HttpUserAgent string `json:"http_user_agent"`
}
