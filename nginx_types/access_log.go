package nginx_types

import (
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
)

type AccessLog struct {
	enrichment.CommonFields

	AccessLogCommonFields
	Status        int       `json:"status"`
	BodyBytesSent int       `json:"body_bytes_sent"`
	Timestamp     time.Time `json:"timestamp"`
}

type RawAccessLog struct {
	AccessLogCommonFields
	Status        string `json:"status"`
	BodyBytesSent string `json:"body_bytes_sent"`
}

type AccessLogCommonFields struct {
	RemoteAddr    string `json:"remote_addr"`
	RemoteUser    string `json:"remote_user"`
	TimeLocal     string `json:"time_local"`
	Request       string `json:"request"`
	HttpReferer   string `json:"http_referer"`
	HttpUserAgent string `json:"http_user_agent"`
}
