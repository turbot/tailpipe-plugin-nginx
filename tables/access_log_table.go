package tables

import (
	"fmt"
	"time"
	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-nginx/models"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const AccessLogTableIdentifier = "nginx_access_log"

type AccessLogTable struct {
	table.TableBase[*AccessLogTableConfig]
}

func NewAccessLogTable() table.Table {
	return &AccessLogTable{}
}

func (t *AccessLogTable) Identifier() string {
	return AccessLogTableIdentifier
}

func (t *AccessLogTable) GetRowSchema() any {
	return models.AccessLog{}
}

func (t *AccessLogTable) GetConfigSchema() parse.Config {
	return &AccessLogTableConfig{}
}

func (t *AccessLogTable) EnrichRow(row any, sourceEnrichmentFields *enrichment.CommonFields) (any, error) {
	item, ok := row.(models.AccessLog)
	if !ok {
		return nil, fmt.Errorf("invalid row type %T, expected AccessLog", row)
	}
	
	if sourceEnrichmentFields == nil {
		return nil, fmt.Errorf("AccessLogTable EnrichRow called with nil sourceEnrichmentFields")
	}

	item.CommonFields = *sourceEnrichmentFields

	// Populate required fields
	item.TpID = xid.New().String()
	item.TpTimestamp = helpers.UnixMillis(item.TimeLocal.UnixNano() / int64(time.Millisecond))
	item.TpPartition = AccessLogTableIdentifier
	item.TpIndex = item.ServerName
	item.TpDate = item.TimeLocal.Format("2006-01-02")
	
	// Split date components
	item.TpYear = item.TimeLocal.Year()
	item.TpMonth = int(item.TimeLocal.Month())
	item.TpDay = item.TimeLocal.Day()

	// Enrichment fields
	item.TpSourceName = AccessLogTableIdentifier
	item.TpSourceType = "nginx_access_log"
	item.TpSourceLocation = sourceEnrichmentFields.TpSourceLocation
	item.TpIngestTimestamp = helpers.UnixMillis(time.Now().UnixNano() / int64(time.Millisecond))

	// IP addresses
	if item.RemoteAddr != "" {
		item.TpSourceIP = &item.RemoteAddr
		item.TpIps = append(item.TpIps, item.RemoteAddr)
	}

	// Usernames
	if item.RemoteUser != "-" {
		item.TpUsernames = append(item.TpUsernames, item.RemoteUser)
	}

	// Domains
	if item.ServerName != "" {
		item.TpDomains = append(item.TpDomains, item.ServerName)
	}

	return item, nil
}