package tables

import (
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/turbot/tailpipe-plugin-nginx/config"
	"github.com/turbot/tailpipe-plugin-nginx/rows"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/table"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

const defaultLogFormat = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
const AccessLogTableIdentifier = "nginx_access_log"

// init registers the table
func init() {
	table.RegisterTable[*rows.AccessLog, *AccessLogTable]()
}

// AccessLogTable - table for nginx access logs
type AccessLogTable struct {
	table.TableImpl[*rows.AccessLog, *AccessLogTableConfig, *config.NginxConnection]
}

func (c *AccessLogTable) Identifier() string {
	return AccessLogTableIdentifier
}

func (c *AccessLogTable) SupportedSources() []*table.SourceMetadata[*rows.AccessLog] {
	return []*table.SourceMetadata[*rows.AccessLog]{
		{
			// any artifact source
			SourceName: constants.ArtifactSourceIdentifier,
			MapperFunc: c.initMapper(),
			Options: []row_source.RowSourceOption{
				artifact_source.WithRowPerLine(),
			},
		},
	}
}

func (c *AccessLogTable) initMapper() func() table.Mapper[*rows.AccessLog] {
	logFormat := defaultLogFormat
	if c.Config != nil && c.Config.LogFormat != nil {
		logFormat = *c.Config.LogFormat
	}

	f := func() table.Mapper[*rows.AccessLog] {
		return table.NewDelimitedLineMapper(rows.NewAccessLog, logFormat)
	}
	return f
}

func (c *AccessLogTable) GetRowSchema() types.RowStruct {
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
		row.TpDate = row.Timestamp.Truncate(24 * time.Hour)
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
