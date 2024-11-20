package mappers

import (
	"regexp"
)

type NginxAccessLogMapper struct{}

func NewNginxAccessLogMapper() *NginxAccessLogMapper {
	return &NginxAccessLogMapper{}
}

var nginxRegex = regexp.MustCompile(`^(?P<remote_addr>[^ ]+) (?P<remote_user>[^ ]+) (?P<local_user>[^ ]+) \[(?P<time_local>[^\]]+)\] "(?P<method>[A-Z]+) (?P<uri>[^ ]+) HTTP/(?P<http_version>[^ ]+)" (?P<status>\d{3}) (?P<bytes_sent>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"`)


func (m *NginxAccessLogMapper) Identifier() string {
	return "nginx_log_mapper"
}
