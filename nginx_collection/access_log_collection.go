package nginx_collection

import (
	"context"
	"fmt"
	"github.com/turbot/tailpipe-plugin-nginx/nginx_source"
	"github.com/turbot/tailpipe-plugin-sdk/artifact"
	"github.com/turbot/tailpipe-plugin-sdk/paging"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-nginx/nginx_types"
	"github.com/turbot/tailpipe-plugin-sdk/collection"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
)

// AccessLogCollection - collection for nginx access logs
type AccessLogCollection struct {
	collection.Base

	Config *AccessLogCollectionConfig
}

func NewAccessLogCollection() plugin.Collection {
	return &AccessLogCollection{}
}

func (c *AccessLogCollection) Identifier() string {
	return "nginx_access_log"
}

func (c *AccessLogCollection) GetConfigSchema() any {
	return AccessLogCollectionConfig{}
}

func (c *AccessLogCollection) GetRowSchema() any {
	return nginx_types.AccessLog{}
}

func (c *AccessLogCollection) GetPagingDataSchema() (paging.Data, error) {
	return nginx_source.NewAccessLogPaging(), nil
}

func (c *AccessLogCollection) Init(ctx context.Context, config []byte) error {
	defaultLogFormat := `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

	// TODO: #config use actual configuration (& validate, etc)
	cfg := &AccessLogCollectionConfig{
		Paths:     []string{"/Users/graza/tailpipe_data/nginx_access_logs"},
		LogFormat: &defaultLogFormat,
	}

	c.Config = cfg

	// TODO: #config create source from config
	source, err := c.getSource(ctx, cfg)
	if err != nil {
		return err
	}
	return c.AddSource(source)
}

func (c *AccessLogCollection) getSource(ctx context.Context, config *AccessLogCollectionConfig) (plugin.RowSource, error) {
	// TODO: #config create source from config ~ probably in Init method...

	artifactSource := artifact.NewFileSystemSource(&artifact.FileSystemSourceConfig{
		Paths:      config.Paths,
		Extensions: []string{".log-20240729"},
	})

	pagingData, err := c.GetPagingDataSchema()
	if err != nil {
		return nil, fmt.Errorf("error creating paging data: %w", err)
	}

	source, err := row_source.NewArtifactRowSource(artifactSource, pagingData, row_source.WithRowPerLine(), row_source.WithMapper(nginx_source.NewAccessLogMapper()))
	if err != nil {
		return nil, fmt.Errorf("error creating artifact row source: %w", err)
	}

	return source, nil
}

// EnrichRow NOTE: Receives RawAccessLog & returns AccessLog
func (c *AccessLogCollection) EnrichRow(row any, sourceEnrichmentFields *enrichment.CommonFields) (any, error) {
	ecf := enrichment.CommonFields{}

	// initialize the enrichment fields to any fields provided by the source
	if sourceEnrichmentFields != nil {
		ecf = *sourceEnrichmentFields
	}

	rawRecord, ok := row.(nginx_types.RawAccessLog)
	if !ok {
		return nil, fmt.Errorf("invalid row type: %T, expected nginx_types.RawAccessLog", row)
	}

	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", rawRecord.TimeLocal)
	if err != nil {
		return nil, fmt.Errorf("error parsing time: %w", err)
	}

	record := nginx_types.AccessLog{
		CommonFields: ecf,
		RawAccessLog: rawRecord,
		Timestamp:    t,
	}

	// Record standardization
	record.TpID = xid.New().String()
	record.TpIngestTimestamp = helpers.UnixMillis(time.Now().UnixNano() / int64(time.Millisecond))
	record.TpSourceType = "nginx_access_log" // TODO: #refactor move to source?
	record.TpSourceIP = &rawRecord.RemoteAddr
	record.TpIps = append(record.TpIps, rawRecord.RemoteAddr)

	// Hive Fields
	record.TpCollection = c.Identifier()
	record.TpConnection = c.Identifier() // TODO: #refactor figure out how to get connection
	record.TpYear = int32(t.Year())
	record.TpMonth = int32(t.Month())
	record.TpDay = int32(t.Day())

	return nil, err
}

// NOTE: Mapper could be the parser of the log file -> log line decode struct from log line
// NOTE: ^ Could also return map[string]string for the log line and then utilise this

// NOTE: LogFormat vars should match json tags - marshall map to json -> unmarshal to struct
// NOTE: ^ Then need to populate common fields from RAW log line
