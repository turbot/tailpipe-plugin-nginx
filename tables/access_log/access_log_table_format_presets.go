package access_log

var defaultAccessLogTableFormat = &AccessLogTableFormat{
	Name:   "default",
	Layout: `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`,
}

var AccessLogTableFormatPresets = []*AccessLogTableFormat{
	defaultAccessLogTableFormat,
}
