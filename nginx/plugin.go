package nginx

import (
	"github.com/turbot/tailpipe-plugin-nginx/config"
	"github.com/turbot/tailpipe-plugin-nginx/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

type Plugin struct {
	plugin.PluginImpl
}

func NewPlugin() (plugin.TailpipePlugin, error) {
	p := &Plugin{
		PluginImpl: plugin.NewPluginImpl("nginx", config.NewNginxConnection),
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
