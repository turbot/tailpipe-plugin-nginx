package access_log

import (
	"errors"
	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
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

// GetSupportedFormats returns a map of the formats that this table supports, including the default format
func (c *AccessLogTable) GetSupportedFormats() *formats.SupportedFormats {
	return &formats.SupportedFormats{
		// map of constructors of ALL supported formats (built in and custom)
		Formats: map[string]func() formats.Format{
			AccessLogTableIdentifier:    NewAccessLogTableFormat,
			constants.SourceFormatRegex: formats.NewRegex,
		},
		// which format is the default for this table
		DefaultFormat: defaultAccessLogTableFormat,
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
				Type:        "TIMESTAMP",
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
	// tp_timestamp / tp_date can be parsed from time_local OR time_iso8601
	// Do this before row.Enrich so that it is set and can be parsed/formatted correctly along with tp_date (save duplicating code)
	if ts, ok := row.GetSourceValue("time_local"); ok && ts != AccessLogTableNilValue {
		t, err := helpers.ParseTime(ts)
		if err != nil {
			return nil, err
		}
		row.OutputColumns[constants.TpTimestamp] = *t
	} else if ts, ok = row.GetSourceValue("time_iso8601"); ok && ts != AccessLogTableNilValue {
		t, err := helpers.ParseTime(ts)
		if err != nil {
			return nil, err
		}

		row.OutputColumns[constants.TpTimestamp] = *t
	} else {
		return nil, errors.New("no timestamp found in row")
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
		row.OutputColumns["tp_ips"] = ips
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
		row.OutputColumns["tp_domains"] = domains
		row.OutputColumns["tp_akas"] = domains
	}

	// tp_usernames
	var usernames []string
	if remoteUser, ok := row.GetSourceValue("remote_user"); ok && remoteUser != AccessLogTableNilValue {
		usernames = append(usernames, remoteUser)
	}
	if len(usernames) > 0 {
		row.OutputColumns["tp_usernames"] = usernames
	}

	// now call the base class to do the rest of the enrichment
	return c.CustomTableImpl.EnrichRow(row, sourceEnrichmentFields)
}
