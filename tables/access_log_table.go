package tables

import (
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/turbot/tailpipe-plugin-nginx/rows"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const defaultLogFormat = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
const AccessLogTableIdentifier = "nginx_access_log"

// init registers the table
func init() {
	// Register the table, with type parameters:
	// 1. row struct
	// 2. table config struct
	// 3. table implementation
	table.RegisterTable[*rows.AccessLog, *AccessLogTableConfig, *AccessLogTable]()
}

// AccessLogTable - table for nginx access logs
type AccessLogTable struct {
}

func (c *AccessLogTable) Identifier() string {
	return AccessLogTableIdentifier
}

func (c *AccessLogTable) SupportedSources(config *AccessLogTableConfig) []*table.SourceMetadata[*rows.AccessLog] {
	return []*table.SourceMetadata[*rows.AccessLog]{
		{
			// any artifact source
			SourceName: constants.ArtifactSourceIdentifier,
			MapperFunc: c.initMapper(config),
			Options: []row_source.RowSourceOption{
				artifact_source.WithRowPerLine(),
			},
		},
	}
}

func (c *AccessLogTable) initMapper(config *AccessLogTableConfig) func() table.Mapper[*rows.AccessLog] {
	logFormat := defaultLogFormat
	if config != nil && config.LogFormat != nil {
		logFormat = *config.LogFormat
	}

	f := func() table.Mapper[*rows.AccessLog] {
		return table.NewDelimitedLineMapper(rows.NewAccessLog, logFormat)
	}
	return f
}

func (c *AccessLogTable) EnrichRow(row *rows.AccessLog, sourceEnrichmentFields *enrichment.CommonFields) (*rows.AccessLog, error) {

	// TODO: #validate ensure we have either `time_local` or `time_iso8601` field as without one of these we can't populate timestamp...

	// Build record and add any source enrichment fields
	if sourceEnrichmentFields != nil {
		row.CommonFields = *sourceEnrichmentFields
	}

	// Record standardization
	row.TpID = xid.New().String()
	row.TpIngestTimestamp = time.Now()
	row.TpTimestamp = *row.Timestamp
	row.TpDate = row.TpTimestamp.Truncate(24 * time.Hour)

	path := filepath.Dir(*row.TpSourceLocation) //  /home/jon/tpsrc/tailpipe-plugin-nginx/tests/dev2/access.log.1
	parts := strings.Split(path, string(filepath.Separator))
	if len(parts) >= 2 {
		row.TpIndex = parts[len(parts)-1]
	} else {
		row.TpIndex = "unknown"
	}


// IP handling
if row.RemoteAddr != nil {
	row.TpSourceIP = row.RemoteAddr
	row.TpIps = []string{*row.RemoteAddr}
}

// Tags enrichment
tags := make([]string, 0)
if row.Method != nil {
	tags = append(tags, "method:"+*row.Method)
}
if row.Status != nil {
	if *row.Status >= 400 {
		tags = append(tags, "error")
		if *row.Status >= 500 {
			tags = append(tags, "server_error")
		} else {
			tags = append(tags, "client_error")
		}
	}
}
if len(tags) > 0 {
	row.TpTags = tags
}

// Users
if *row.RemoteUser != "" && *row.RemoteUser != "-" {
	row.TpUsernames = append(row.TpUsernames, *row.RemoteUser)
}

// Domain extraction
if row.Path != nil {
	// Extract domain from path if it looks like a full URL
	if strings.HasPrefix(*row.Path, "http://") || strings.HasPrefix(*row.Path, "https://") {
		if u, err := url.Parse(*row.Path); err == nil && u.Hostname() != "" {
			row.TpDomains = append(row.TpDomains, u.Hostname())
		}
	}
	// Add path to AKAs
	row.TpAkas = append(row.TpAkas, *row.Path)
}

	return row, nil
}
