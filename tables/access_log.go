package tables

import (
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
