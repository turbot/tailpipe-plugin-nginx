package tables

import (
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
	row.TpIndex = c.Identifier() // TODO: #refactor figure out how to get connection

	return row, nil
}
