package tables

import (
	"fmt"
	"strconv"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-nginx/mappers"
	"github.com/turbot/tailpipe-plugin-nginx/models"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

// AccessLogTable - table for nginx access logs
type AccessLogTable struct {
	table.TableBase[*AccessLogTableConfig]
}

func NewAccessLogCollection() table.Table {
	return &AccessLogTable{}
}

func (c *AccessLogTable) Identifier() string {
	return "nginx_access_log"
}

func (c *AccessLogTable) GetSourceOptions(sourceType string) []row_source.RowSourceOption {
	if c.Config == nil {
		c.Config = &AccessLogTableConfig{}
	}
	if c.Config.LogFormat == nil {
		defaultLogFormat := `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
		c.Config.LogFormat = &defaultLogFormat
	}

	return []row_source.RowSourceOption{
		artifact_source.WithRowPerLine(),
		artifact_source.WithArtifactMapper(mappers.NewAccessLogMapper(*c.Config.LogFormat)),
	}
}

func (c *AccessLogTable) GetRowSchema() any {
	return models.AccessLog{}
}

func (c *AccessLogTable) GetConfigSchema() parse.Config {
	return &AccessLogTableConfig{}
}

// EnrichRow NOTE: Receives RawAccessLog & returns AccessLog
func (c *AccessLogTable) EnrichRow(row any, sourceEnrichmentFields *enrichment.CommonFields) (any, error) {
	// short-circuit for unexpected row type
	rawRecord, ok := row.(map[string]string)
	if !ok {
		return nil, fmt.Errorf("invalid row type: %T, expected map[string]string", row)
	}

	// TODO: #validate ensure we have either `time_local` or `time_iso8601` field as without one of these we can't populate timestamp...

	// Build record and add any source enrichment fields
	var record models.AccessLog
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
	record.TpTimestamp = helpers.UnixMillis(record.Timestamp.UnixNano() / int64(time.Millisecond))
	record.TpSourceType = "nginx_access_log" // TODO: #refactor move to source?

	// Hive Fields
	record.TpPartition = c.Identifier()
	record.TpIndex = c.Identifier() // TODO: #refactor figure out how to get connection
	record.TpDate = record.Timestamp.Format("2006-01-02")

	return record, nil
}
