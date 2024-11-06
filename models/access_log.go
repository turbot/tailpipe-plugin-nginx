package models

import (
    "time"
    "github.com/turbot/tailpipe-plugin-sdk/enrichment"
)

type AccessLog struct {
    // embed required enrichment fields
    enrichment.CommonFields

    // Core NGINX fields
    RemoteAddr    string    `json:"remote_addr"`
    RemoteUser    string    `json:"remote_user"`
    TimeLocal     time.Time `json:"time_local"`
    Method        string    `json:"method"`
    URI           string    `json:"uri"`
    Protocol      string    `json:"protocol"`
    Status        int       `json:"status"`
    BytesSent     int64     `json:"bytes_sent"`
    Referer       string    `json:"referer"`
    UserAgent     string    `json:"user_agent"`
    ServerName    string    `json:"server_name"`

    // Optional extended fields
    Request     string `json:"request,omitempty"`
    TimeIso8601 string `json:"time_iso8601,omitempty"`

    // Time component fields for partitioning and querying
    TpYear  int `json:"tp_year"`
    TpMonth int `json:"tp_month"`
    TpDay   int `json:"tp_day"`
}

// NewAccessLog creates a new AccessLog instance
func NewAccessLog() *AccessLog {
    return &AccessLog{
        ServerName: "default",
    }
}