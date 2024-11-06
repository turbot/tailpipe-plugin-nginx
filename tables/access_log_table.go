package tables

import (
	"fmt"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-nginx/config"
	"github.com/turbot/tailpipe-plugin-nginx/models"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const AccessLogTableIdentifier = "nginx_access_log"

type AccessLogTable struct {
	table.TableImpl[*models.AccessLog, *AccessLogTableConfig, *config.NginxConnection]
}

func NewAccessLogTable() table.Table {
	return &AccessLogTable{}
}

func (t *AccessLogTable) Identifier() string {
	return AccessLogTableIdentifier
}

func (t *AccessLogTable) GetRowSchema() any {
	return &models.AccessLog{}
}

func (t *AccessLogTable) GetConfigSchema() parse.Config {
	return &AccessLogTableConfig{}
}

func (t *AccessLogTable) EnrichRow(row *models.AccessLog, sourceEnrichmentFields *enrichment.CommonFields) (*models.AccessLog, error) {
	if sourceEnrichmentFields == nil {
		return nil, fmt.Errorf("AccessLogTable EnrichRow called with nil sourceEnrichmentFields")
	}
	if sourceEnrichmentFields.TpSourceName == "" {
		return nil, fmt.Errorf("AccessLogTable EnrichRow called with TpSourceName unset in sourceEnrichmentFields")
	}

	// Embed the source enrichment fields
	row.CommonFields = *sourceEnrichmentFields

	// Populate required fields
	row.TpID = xid.New().String()
	row.TpTimestamp = helpers.UnixMillis(row.TimeLocal.UnixNano() / int64(time.Millisecond))
	row.TpPartition = AccessLogTableIdentifier
	row.TpIndex = row.ServerName
	row.TpDate = row.TimeLocal.Format("2006-01-02")

	// Split date components
	row.TpYear = row.TimeLocal.Year()
	row.TpMonth = int(row.TimeLocal.Month())
	row.TpDay = row.TimeLocal.Day()

	// IP addresses
	if row.RemoteAddr != "" {
		row.TpSourceIP = &row.RemoteAddr
		row.TpIps = append(row.TpIps, row.RemoteAddr)
	}

	// Usernames
	if row.RemoteUser != "-" && row.RemoteUser != "" {
		row.TpUsernames = append(row.TpUsernames, row.RemoteUser)
	}

	// Domains
	if row.ServerName != "" {
		row.TpDomains = append(row.TpDomains, row.ServerName)
	}

	row.TpIngestTimestamp = helpers.UnixMillis(time.Now().UnixNano() / int64(time.Millisecond))

	return row, nil
}