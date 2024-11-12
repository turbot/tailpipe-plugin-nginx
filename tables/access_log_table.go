package tables

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/turbot/tailpipe-plugin-nginx/config"
	"github.com/turbot/tailpipe-plugin-nginx/rows"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
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

func (c *AccessLogTable) EnrichRow(row *rows.AccessLog, sourceEnrichmentFields *enrichment.CommonFields) (*rows.AccessLog, error) {
	// Build record and add any source enrichment fields
	if sourceEnrichmentFields != nil {
		row.CommonFields = *sourceEnrichmentFields
	}

	// Record standardization
	row.TpID = xid.New().String()
	row.TpIngestTimestamp = time.Now()

	// Timestamp checks
	if row.Timestamp != nil {
		row.TpTimestamp = *row.Timestamp
		row.TpDate = row.Timestamp.Format("2006-01-02")
	}

	// Hive Fields
	//row.TpIndex = c.Identifier()
	filename := filepath.Base(*row.TpSourceLocation)
	row.TpIndex = filename

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
