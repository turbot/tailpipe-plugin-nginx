package access_log

import sdkformats "github.com/turbot/tailpipe-plugin-sdk/formats"

var defaultAccessLogTableFormat = &AccessLogTableFormat{
	Name:        "combined",
	Description: "Predefined Nginx combined log format.",
	Layout:      `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`,
}

var AccessLogTableFormatPresets = []sdkformats.Format{
	defaultAccessLogTableFormat,
}
