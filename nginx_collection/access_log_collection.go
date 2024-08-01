package nginx_collection

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-nginx/nginx_source"
	"github.com/turbot/tailpipe-plugin-nginx/nginx_types"
	"github.com/turbot/tailpipe-plugin-sdk/artifact"
	"github.com/turbot/tailpipe-plugin-sdk/collection"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/paging"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
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
		Extensions: []string{".log"},
	})

	pagingData, err := c.GetPagingDataSchema()
	if err != nil {
		return nil, fmt.Errorf("error creating paging data: %w", err)
	}

	source, err := row_source.NewArtifactRowSource(artifactSource, pagingData, row_source.WithRowPerLine(), row_source.WithMapper(nginx_source.NewAccessLogMapper(*c.Config.LogFormat)))
	if err != nil {
		return nil, fmt.Errorf("error creating artifact row source: %w", err)
	}

	return source, nil
}

// EnrichRow NOTE: Receives RawAccessLog & returns AccessLog
func (c *AccessLogCollection) EnrichRow(row any, sourceEnrichmentFields *enrichment.CommonFields) (any, error) {
	// short-circuit for unexpected row type
	rawRecord, ok := row.(map[string]string)
	if !ok {
		return nil, fmt.Errorf("invalid row type: %T, expected map[string]string", row)
	}

	// TODO: #validate ensure we have either `time_local` or `time_iso8601` field as without one of these we can't populate timestamp...

	// Build record and add any source enrichment fields
	var record nginx_types.AccessLog
	if sourceEnrichmentFields != nil {
		record.CommonFields = *sourceEnrichmentFields
	}

	for key, value := range rawRecord {
		switch key {
		case "remote_addr":
			record.RemoteAddr = &value
			record.TpSourceIP = &value
			record.TpIps = append(record.TpIps, value)
		case "remote_user":
			record.RemoteUser = &value
			if value != "" && value != "-" {
				record.TpUsernames = append(record.TpUsernames, value)
			}
		case "time_local":
			t, err := time.Parse("02/Jan/2006:15:04:05 -0700", value)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
			iso := t.Format(time.RFC3339)
			record.TimeLocal = &value
			record.TimeIso8601 = &iso
			record.Timestamp = &t
		case "time_iso8601":
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, fmt.Errorf("error parsing time: %w", err)
			}
			record.TimeIso8601 = &value
			record.Timestamp = &t
		case "request":
			record.Request = &value
		case "status":
			status, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing status to int: %w", err)
			}
			record.Status = &status
		case "body_bytes_sent":
			bbs, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing body bytes sent to int: %w", err)
			}
			record.BodyBytesSent = &bbs
		case "http_referer":
			record.HttpReferer = &value
		case "http_user_agent":
			record.HttpUserAgent = &value
		}

	}

	// Record standardization
	record.TpID = xid.New().String()
	record.TpIngestTimestamp = helpers.UnixMillis(time.Now().UnixNano() / int64(time.Millisecond))
	record.TpSourceType = "nginx_access_log" // TODO: #refactor move to source?

	// Hive Fields
	record.TpCollection = c.Identifier()
	record.TpConnection = c.Identifier() // TODO: #refactor figure out how to get connection
	record.TpYear = int32(record.Timestamp.Year())
	record.TpMonth = int32(record.Timestamp.Month())
	record.TpDay = int32(record.Timestamp.Day())

	return record, nil
}

// NOTE: Mapper could be the parser of the log file -> log line decode struct from log line
// NOTE: ^ Could also return map[string]string for the log line and then utilise this

// NOTE: LogFormat vars should match json tags - marshall map to json -> unmarshal to struct
// NOTE: ^ Then need to populate common fields from RAW log line
