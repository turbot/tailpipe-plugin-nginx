package nginx

import (
	"github.com/turbot/tailpipe-plugin-nginx/tables/access_log"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const PluginName = "nginx"

func init() {
	// Register the table, with type parameter:
	// 1. table type
	table.RegisterPredefinedCustomTable[*access_log.AccessLogTable]()
}

type Plugin struct {
	plugin.PluginImpl
}

func NewPlugin() (_ plugin.TailpipePlugin, err error) {
	p := &Plugin{
		PluginImpl: plugin.NewPluginImpl(PluginName),
	}

	return p, nil
}
