package nginx_source

import "github.com/turbot/tailpipe-plugin-sdk/paging"

// TODO: #paging figure out paging for nginx access logs - this is a placeholder

type AccessLogPaging struct {
}

func NewAccessLogPaging() *AccessLogPaging {
	return &AccessLogPaging{}
}

func (a *AccessLogPaging) Update(data paging.Data) error {
	return nil
}
