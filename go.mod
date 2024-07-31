module github.com/turbot/tailpipe-plugin-nginx

go 1.22.2

toolchain go1.22.3

replace github.com/turbot/tailpipe-plugin-sdk => ../tailpipe-plugin-sdk

require (
	github.com/rs/xid v1.5.0
	github.com/turbot/tailpipe-plugin-sdk v0.0.0
)