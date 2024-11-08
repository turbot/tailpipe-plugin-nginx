package tables

import (
	"context"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-nginx/config"
	"github.com/turbot/tailpipe-plugin-nginx/rows"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/table"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

const defaultLogFormat = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

// AccessLogTable - table for nginx access logs
type AccessLogTable struct {
	table.TableImpl[*rows.AccessLog, *AccessLogTableConfig, *config.NginxConnection]
}

func NewAccessLogCollection() table.Table {
	return &AccessLogTable{}
}

func (c *AccessLogTable) Identifier() string {
	return "nginx_access_log"
}

func (c *AccessLogTable) Init(ctx context.Context, connectionSchemaProvider table.ConnectionSchemaProvider, req *types.CollectRequest) error {
	// call base init
	if err := c.TableImpl.Init(ctx, connectionSchemaProvider, req); err != nil {
		return err
	}

	c.initMapper()
	return nil
}

func (c *AccessLogTable) initMapper() {
	// TODO switch on source

	// TODO KAI make sure tables add NewCloudwatchMapper if needed
	// NOTE: add the cloudwatch mapper to ensure rows are in correct format
	//s.AddMappers(artifact_mapper.NewCloudwatchMapper())

	// if the source is an artifact source, we need a mapper
	logFormat := defaultLogFormat
	if c.Config != nil && c.Config.LogFormat != nil {
		logFormat = *c.Config.LogFormat
	}
	c.Mapper = table.NewDelimitedLineMapper(rows.NewAccessLog, logFormat)
}

func (c *AccessLogTable) GetSourceOptions(sourceType string) []row_source.RowSourceOption {
	return []row_source.RowSourceOption{
		artifact_source.WithRowPerLine(),
	}
}

func (c *AccessLogTable) GetRowSchema() any {
	return rows.NewAccessLog()
}

func (c *AccessLogTable) GetConfigSchema() parse.Config {
	return &AccessLogTableConfig{}
}

// EnrichRow NOTE: Receives RawAccessLog & returns AccessLog
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

	// Hive Fields
	row.TpIndex = c.Identifier() // TODO: #refactor figure out how to get connection
	row.TpDate = row.Timestamp.Format("2006-01-02")

	return row, nil
}
