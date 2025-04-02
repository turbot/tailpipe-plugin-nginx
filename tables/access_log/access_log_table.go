package access_log

import (
	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/error_types"
	"github.com/turbot/tailpipe-plugin-sdk/formats"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/schema"
	"github.com/turbot/tailpipe-plugin-sdk/table"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

const AccessLogTableIdentifier = "nginx_access_log"

const AccessLogTableNilValue = "-"

// AccessLogTable - table for nginx access logs
type AccessLogTable struct {
	table.CustomTableImpl
}

func (c *AccessLogTable) Identifier() string {
	return AccessLogTableIdentifier
}

func (c *AccessLogTable) GetDefaultFormat() formats.Format {
	return defaultAccessLogTableFormat
}

func (c *AccessLogTable) GetTableDefinition() *schema.TableSchema {
	return &schema.TableSchema{
		Name: AccessLogTableIdentifier,
		Columns: []*schema.ColumnSchema{
			{
				ColumnName: "tp_source_ip",
				SourceName: "remote_addr",
			},
			// default format fields
			{
				ColumnName:  "remote_addr",
				Description: "Client IP address",
				Type:        "varchar",
			},
			{
				ColumnName:  "host",
				Description: "Hostname from the 'Host' request header, or the server name matching the request",
				Type:        "varchar",
			},
			{
				ColumnName:  "remote_user",
				Description: "Authenticated user name",
				Type:        "varchar",
			},
			{
				ColumnName:  "time_local",
				Description: "Local time in Common Log Format",
				Type:        "varchar",
			},
			{
				ColumnName:  "request_method",
				Description: "Request method (GET, POST, etc.)",
				Type:        "varchar",
			},
			{
				ColumnName:  "request_uri",
				Description: "Full original request URI, including arguments",
				Type:        "varchar",
			},
			{
				ColumnName:  "server_protocol",
				Description: "Protocol used in the request (e.g. 'HTTP/1.1')",
				Type:        "varchar",
			},
			{
				ColumnName:  "status",
				Description: "Response status code",
				Type:        "integer",
			},
			{
				ColumnName:  "body_bytes_sent",
				Description: "Number of bytes sent to the client, excluding headers",
				Type:        "integer",
			},
			{
				ColumnName:  "http_referer",
				Description: "Value of the 'Referer' request header",
				Type:        "varchar",
			},
			{
				ColumnName:  "http_user_agent",
				Description: "Value of the 'User-Agent' request header",
				Type:        "varchar",
			},
			// additional client request variables
			{
				ColumnName:  "scheme",
				Description: "Request scheme (http or https)",
				Type:        "varchar",
			},
			{
				ColumnName:  "http_host",
				Description: "Value of the 'Host' request header",
				Type:        "varchar",
			},
			{
				ColumnName:  "http_cookie",
				Description: "Value of the 'Cookie' request header",
				Type:        "varchar",
			},
			{
				ColumnName:  "content_length",
				Description: "Value of the 'Content-Length' request header",
				Type:        "integer",
			},
			{
				ColumnName:  "content_type",
				Description: "Value of the 'Content-Type' request header",
				Type:        "varchar",
			},
			{
				ColumnName:  "request_length",
				Description: "Length of the request (including request line, headers, and body)",
				Type:        "integer",
			},
			// additional server variables
			{
				ColumnName:  "server_name",
				Description: "Name of the server handling the request",
				Type:        "varchar",
			},
			{
				ColumnName:  "server_addr",
				Description: "Server address",
				Type:        "varchar",
			},
			{
				ColumnName:  "server_port",
				Description: "Port on which the request was received",
				Type:        "integer",
			},
			// additional connection variables
			{
				ColumnName:  "connection",
				Description: "Connection serial number",
				Type:        "varchar",
			},
			{
				ColumnName:  "connection_requests",
				Description: "Number of requests made through this connection",
				Type:        "integer",
			},
			{
				ColumnName:  "msec",
				Description: "Current time in seconds with milliseconds resolution",
				Type:        "float",
			},
			{
				ColumnName:  "time_iso8601",
				Description: "Local time in ISO 8601 format",
				Type:        "timestamp",
			},
			// additional response variables
			{
				ColumnName:  "bytes_sent",
				Description: "Total number of bytes sent to the client",
				Type:        "integer",
			},
			{
				ColumnName:  "request_time",
				Description: "Time spent processing the request, in seconds with milliseconds resolution",
				Type:        "float",
			},
			{
				ColumnName:  "pipe",
				Description: "Indicates if the request was pipelined (p) or not (.)",
				Type:        "varchar",
			},
			// additional upstream variables
			{
				ColumnName:  "upstream_addr",
				Description: "Address of the upstream server handling the request",
				Type:        "varchar",
			},
			{
				ColumnName:  "upstream_status",
				Description: "Status code returned by the upstream server",
				Type:        "integer",
			},
			{
				ColumnName:  "upstream_connect_time",
				Description: "Time spent establishing a connection with the upstream server",
				Type:        "float",
			},
			{
				ColumnName:  "upstream_header_time",
				Description: "Time between establishing a connection and receiving the first byte of the response header from the upstream server",
				Type:        "float",
			},
			{
				ColumnName:  "upstream_response_time",
				Description: "Time between establishing a connection and receiving the last byte of the response body from the upstream server",
				Type:        "float",
			},
			// additional ssl variables
			{
				ColumnName:  "ssl_protocol",
				Description: "SSL protocol used",
				Type:        "varchar",
			},
			{
				ColumnName:  "ssl_cipher",
				Description: "SSL cipher used",
				Type:        "varchar",
			},
			{
				ColumnName:  "ssl_session_id",
				Description: "SSL session identifier",
				Type:        "varchar",
			},
			{
				ColumnName:  "ssl_client_cert",
				Description: "Client certificate in PEM format",
				Type:        "varchar",
			},
			// additional miscellaneous variables
			{
				ColumnName:  "gzip_ratio",
				Description: "Compression ratio achieved by gzip",
				Type:        "float",
			},
		},
		NullValue: AccessLogTableNilValue,
	}
}

func (c *AccessLogTable) GetSourceMetadata() ([]*table.SourceMetadata[*types.DynamicRow], error) {
	// ask our CustomTableImpl for the mapper
	mapper, err := c.Format.GetMapper()
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
	var invalidFields []string

	// tp_timestamp can be parsed from time_local OR time_iso8601
	// We don't have a fallback for Source so we should populate prior to calling c.CustomTableImpl.EnrichRow
	// if neither are set in the source, the base call will throw the missing fields error for tp_timestamp/tp_date
	if ts, ok := row.GetSourceValue("time_local"); ok && ts != AccessLogTableNilValue {
		t, err := helpers.ParseTime(ts)
		if err != nil {
			invalidFields = append(invalidFields, "time_local")
		} else {
			row.OutputColumns[constants.TpTimestamp] = t
		}
	}
	if ts, ok := row.GetSourceValue("time_iso8601"); ok && ts != AccessLogTableNilValue {
		t, err := helpers.ParseTime(ts)
		if err != nil {
			invalidFields = append(invalidFields, "time_iso8601")
		} else {
			row.OutputColumns[constants.TpTimestamp] = t
		}
	}

	if len(invalidFields) > 0 {
		return nil, error_types.NewRowErrorWithFields([]string{}, invalidFields)
	}

	// Enrich Array Based TP Fields as we don't have a mechanism to do this via direct mapping

	//tp_ips
	var ips []string
	if remoteAddr, ok := row.GetSourceValue("remote_addr"); ok {
		ips = append(ips, remoteAddr)
	}
	if serverAddr, ok := row.GetSourceValue("server_addr"); ok {
		ips = append(ips, serverAddr)
	}
	if upstreamAddr, ok := row.GetSourceValue("upstream_addr"); ok {
		ips = append(ips, upstreamAddr)
	}
	if len(ips) > 0 {
		row.OutputColumns[constants.TpIps] = ips
	}

	// tp_domains
	var domains []string
	if host, ok := row.GetSourceValue("host"); ok && host != AccessLogTableNilValue {
		domains = append(domains, host)
	}
	if httpHost, ok := row.GetSourceValue("http_host"); ok && httpHost != AccessLogTableNilValue {
		domains = append(domains, httpHost)
	}
	if len(domains) > 0 {
		row.OutputColumns[constants.TpDomains] = domains
		row.OutputColumns[constants.TpAkas] = domains
	}

	// tp_usernames
	var usernames []string
	if remoteUser, ok := row.GetSourceValue("remote_user"); ok && remoteUser != AccessLogTableNilValue {
		usernames = append(usernames, remoteUser)
	}
	if len(usernames) > 0 {
		row.OutputColumns[constants.TpUsernames] = usernames
	}

	// now call the base class to do the rest of the enrichment
	return c.CustomTableImpl.EnrichRow(row, sourceEnrichmentFields)
}
