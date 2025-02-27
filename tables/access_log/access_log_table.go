package access_log

import (
	"errors"
	"strings"

	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/formats"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/schema"
	"github.com/turbot/tailpipe-plugin-sdk/table"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

const AccessLogTableIdentifier = "nginx_access_log"

// AccessLogTable - table for nginx access logs
type AccessLogTable struct {
	table.CustomTableImpl
}

func (c *AccessLogTable) Identifier() string {
	return AccessLogTableIdentifier
}

// GetSupportedFormats returns a map of the formats that this table supports, including the default format
func (c *AccessLogTable) GetSupportedFormats() *formats.SupportedFormats {
	return &formats.SupportedFormats{
		// map of constructors of ALL supported formats (built in and custom)
		Formats: map[string]func() formats.Format{
			AccessLogTableIdentifier:    NewAccessLogTableFormat,
			constants.SourceFormatRegex: formats.NewRegex,
		},
		// map of instances of supported formats - these may be referenced in HCL config
		FormatInstances: []formats.Format{
			&AccessLogTableFormat{
				Name:   "default",
				Layout: "default - TODO",
			},
		},
		// which format is the default for this table
		DefaultFormat: "default",
	}
}

func (c *AccessLogTable) GetTableDefinition() *schema.TableSchema {
	return &schema.TableSchema{
		Name: AccessLogTableIdentifier,
		Columns: []*schema.ColumnSchema{
			{
				ColumnName: "tp_source_ip",
				SourceName: "remote_addr",
			},
			{
				ColumnName: "tp_usernames",
				SourceName: "remote_user",
			},
			// default format fields
			{
				ColumnName:  "remote_addr",
				Description: "Client IP address",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "host",
				Description: "Hostname from the 'Host' request header, or the server name matching the request",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "remote_user",
				Description: "Authenticated user name",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "time_local",
				Description: "Local time in Common Log Format",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "request_method",
				Description: "Request method (GET, POST, etc.)",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "request_uri",
				Description: "Full original request URI, including arguments",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "server_protocol",
				Description: "Protocol used in the request (e.g. 'HTTP/1.1')",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "status",
				Description: "Response status code",
				Type:        "INTEGER",
			},
			{
				ColumnName:  "body_bytes_sent",
				Description: "Number of bytes sent to the client, excluding headers",
				Type:        "INTEGER",
			},
			{
				ColumnName:  "http_referer",
				Description: "Value of the 'Referer' request header",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "http_user_agent",
				Description: "Value of the 'User-Agent' request header",
				Type:        "VARCHAR",
			},
			// additional client request variables
			{
				ColumnName:  "scheme",
				Description: "Request scheme (http or https)",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "http_host",
				Description: "Value of the 'Host' request header",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "http_cookie",
				Description: "Value of the 'Cookie' request header",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "content_length",
				Description: "Value of the 'Content-Length' request header",
				Type:        "INTEGER",
			},
			{
				ColumnName:  "content_type",
				Description: "Value of the 'Content-Type' request header",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "request_length",
				Description: "Length of the request (including request line, headers, and body)",
				Type:        "INTEGER",
			},
			// additional server variables
			{
				ColumnName:  "server_name",
				Description: "Name of the server handling the request",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "server_addr",
				Description: "Server address",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "server_port",
				Description: "Port on which the request was received",
				Type:        "INTEGER",
			},
			// additional connection variables
			{
				ColumnName:  "connection",
				Description: "Connection serial number",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "connection_requests",
				Description: "Number of requests made through this connection",
				Type:        "INTEGER",
			},
			{
				ColumnName:  "msec",
				Description: "Current time in seconds with milliseconds resolution",
				Type:        "FLOAT",
			},
			{
				ColumnName:  "time_iso8601",
				Description: "Local time in ISO 8601 format",
				Type:        "VARCHAR",
			},
			// additional response variables
			{
				ColumnName:  "bytes_sent",
				Description: "Total number of bytes sent to the client",
				Type:        "INTEGER",
			},
			{
				ColumnName:  "request_time",
				Description: "Time spent processing the request, in seconds with milliseconds resolution",
				Type:        "FLOAT",
			},
			{
				ColumnName:  "pipe",
				Description: "Indicates if the request was pipelined (p) or not (.)",
				Type:        "VARCHAR",
			},
			// additional upstream variables
			{
				ColumnName:  "upstream_addr",
				Description: "Address of the upstream server handling the request",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "upstream_status",
				Description: "Status code returned by the upstream server",
				Type:        "INTEGER",
			},
			{
				ColumnName:  "upstream_connect_time",
				Description: "Time spent establishing a connection with the upstream server",
				Type:        "FLOAT",
			},
			{
				ColumnName:  "upstream_header_time",
				Description: "Time between establishing a connection and receiving the first byte of the response header from the upstream server",
				Type:        "FLOAT",
			},
			{
				ColumnName:  "upstream_response_time",
				Description: "Time between establishing a connection and receiving the last byte of the response body from the upstream server",
				Type:        "FLOAT",
			},
			// additional ssl variables
			{
				ColumnName:  "ssl_protocol",
				Description: "SSL protocol used",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "ssl_cipher",
				Description: "SSL cipher used",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "ssl_session_id",
				Description: "SSL session identifier",
				Type:        "VARCHAR",
			},
			{
				ColumnName:  "ssl_client_cert",
				Description: "Client certificate in PEM format",
				Type:        "VARCHAR",
			},
			// additional miscellaneous variables
			{
				ColumnName:  "gzip_ratio",
				Description: "Compression ratio achieved by gzip",
				Type:        "FLOAT",
			},
		},
		NullValue: "-",
	}
}

func (c *AccessLogTable) GetSourceMetadata() ([]*table.SourceMetadata[*types.DynamicRow], error) {
	// ask our CustomTableImpl for the mapper
	mapper, err := c.GetMapper()
	if err != nil {
		return nil, err
	}

	// which source do we support?
	return []*table.SourceMetadata[*types.DynamicRow]{
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

func (c *AccessLogTable) EnrichRow(row *types.DynamicRow, sourceEnrichmentFields schema.SourceEnrichment) (*types.DynamicRow, error) {
	nilChar := c.GetTableDefinition().NullValue

	// tp_timestamp / tp_date can be parsed from time_local OR time_iso8601
	// Do this before row.Enrich so that it is set and can be parsed/formatted correctly along with tp_date (save duplicating code)
	if ts, ok := row.Columns["time_local"]; ok {
		row.Columns["tp_timestamp"] = ts
	} else if ts, ok = row.Columns["time_iso8601"]; ok {
		row.Columns["tp_timestamp"] = ts
	} else {
		return nil, errors.New("no timestamp found in row")
	}

	// tell the row to enrich itself using any mappings specified in the source format
	err := row.Enrich(sourceEnrichmentFields.CommonFields)
	if err != nil {
		return nil, err
	}

	// Enrich Array Based TP Fields as we don't have a mechanism to do this via direct mapping

	// tp_ips
	var ips []string
	if remoteAddr, ok := row.Columns["remote_addr"]; ok {
		ips = append(ips, remoteAddr)
	}
	if serverAddr, ok := row.Columns["server_addr"]; ok {
		ips = append(ips, serverAddr)
	}
	if upstreamAddr, ok := row.Columns["upstream_addr"]; ok {
		ips = append(ips, upstreamAddr)
	}
	if len(ips) > 0 {
		row.Columns["tp_ips"] = strings.Join(ips, ",")
	}

	// tp_domains
	var domains []string
	if host, ok := row.Columns["host"]; ok && host != nilChar {
		domains = append(domains, host)
	}
	if httpHost, ok := row.Columns["http_host"]; ok && httpHost != nilChar {
		domains = append(domains, httpHost)
	}
	if len(domains) > 0 {
		row.Columns["tp_domains"] = strings.Join(domains, ",")
		row.Columns["tp_akas"] = strings.Join(domains, ",") // TODO: What should be the value of tp_akas?
	}

	return row, nil
}
