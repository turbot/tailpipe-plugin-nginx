package nginx

import (
	"github.com/turbot/tailpipe-plugin-nginx/config"
	"github.com/turbot/tailpipe-plugin-nginx/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

type Plugin struct {
	plugin.PluginBase
}

func NewPlugin() (plugin.TailpipePlugin, error) {
	p := &Plugin{
		PluginBase: plugin.NewPluginBase("nginx", config.NewNginxConnection),
	}

	err := p.RegisterResources(
		&plugin.ResourceFunctions{
			Tables: []func() table.Table{tables.NewAccessLogCollection},
		})
	if err != nil {
		return nil, err
	}

	return p, nil
}
