package models

import (
    "time"
    "github.com/turbot/tailpipe-plugin-sdk/enrichment"
)

type AccessLog struct {
    // embed required enrichment fields
    enrichment.CommonFields

    // NGINX specific fields
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

    // Time component fields for partitioning and querying
    TpYear       int `json:"tp_year"`
    TpMonth      int `json:"tp_month"`
    TpDay        int `json:"tp_day"`
}