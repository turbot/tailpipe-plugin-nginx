package nginx

import (
	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/tailpipe-plugin-nginx/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const PluginName = "nginx"

func init() {
	table.RegisterCollector(table.NewCustomCollector[*tables.AccessLogTable]())
}

type Plugin struct {
	plugin.PluginImpl
}

func NewPlugin() (_ plugin.TailpipePlugin, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = helpers.ToError(r)
		}
	}()

	p := &Plugin{
		PluginImpl: plugin.NewPluginImpl(PluginName),
	}

	return p, nil
}
