package access_log

import (
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/formats"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/schema"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const AccessLogTableIdentifier = "nginx_access_log"

// AccessLogTable - table for nginx access logs
type AccessLogTable struct {
	table.CustomTableImpl
}

func (c *AccessLogTable) Identifier() string {
	return AccessLogTableIdentifier
}

func (c *AccessLogTable) GetFormat() parse.Config {
	return &formats.Regex{
		Layout: `^(?<remote_addr>[^ ]*) (?<host>[^ ]*) (?<remote_user>[^ ]*) \[(?<time_local>[^\]]*)\] "(?<method>\S+)(?: +(?<path>[^"]*?)(?: +(?<http_version>\S*))?)?" (?<status>[^ ]*) (?<body_bytes_sent>[^ ]*)(?: "(?<http_referer>[^"]*)" "(?<http_user_agent>[^"]*)")`,
	}
}

func (c *AccessLogTable) GetTableDefinition() *schema.TableSchema {
	return &schema.TableSchema{
		Name: AccessLogTableIdentifier,
		Columns: []*schema.ColumnSchema{
			{
				ColumnName: "tp_timestamp",
				SourceName: "time_local",
			},
			{
				ColumnName: "tp_date",
				SourceName: "time_local",
			},
			{
				ColumnName: "tp_source_ip",
				SourceName: "remote_addr",
			},
			{
				ColumnName: "tp_ips",
				SourceName: "remote_addr",
			},
			{
				ColumnName: "tp_usernames",
				SourceName: "remote_user",
			},
			{
				ColumnName: "tp_domains",
				SourceName: "path",
			},
			{
				ColumnName: "tp_akas",
				SourceName: "path",
			},
			{
				ColumnName:  "remote_addr",
				Description: "Original source IP from log",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "remote_user",
				Description: "User authenticated in request",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "time_local",
				Description: "Timestamp in local format",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "time_iso_8601",
				Description: "Timestamp in ISO8601 format",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "host",
				Description: "Hostname or virtual host associated with the request, if logged.",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "method",
				Description: "HTTP method (GET, POST, etc.)",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "path",
				Description: "URL path from request",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "http_version",
				Description: "HTTP version",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "status",
				Description: "HTTP response status code",
				Type:        "INTEGER",
			},
			{
				ColumnName:  "body_bytes_sent",
				Description: "Size of response in bytes",
				Type:        "INTEGER",
			},
			{
				ColumnName:  "http_referer",
				Description: "Referer URL",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "http_user_agent",
				Description: "User agent string",
				Type:        "VARCHAR",
			},
		},
		NullValue: "-",
	}
}

func (c *AccessLogTable) GetSourceMetadata() ([]*table.SourceMetadata[*table.DynamicRow], error) {
	// ask our CustomTableImpl for the mapper
	mapper, err := c.GetMapper()
	if err != nil {
		return nil, err
	}

	// which source do we support?
	return []*table.SourceMetadata[*table.DynamicRow]{
		{
			// any artifact source
			SourceName: constants.ArtifactSourceIdentifier,
			Mapper:     mapper,
			Options: []row_source.RowSourceOption{
				artifact_source.WithRowPerLine(),
			},
		},
	}, nil
}
