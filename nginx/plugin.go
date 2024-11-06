package nginx

import (
	"github.com/turbot/tailpipe-plugin-nginx/config"
	"github.com/turbot/tailpipe-plugin-nginx/sources"
	"github.com/turbot/tailpipe-plugin-nginx/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

type Plugin struct {
	plugin.PluginImpl
}

func NewPlugin() (plugin.TailpipePlugin, error) {
	p := &Plugin{
		PluginImpl: plugin.NewPluginImpl("nginx", config.NewNginxConnection),
	}

	// register the tables, sources and mappers that we provide
	resources := &plugin.ResourceFunctions{
		Tables:  []func() table.Table{tables.NewAccessLogTable},
		Sources: []func() row_source.RowSource{sources.NewAccessLogFileSource},
	}

	if err := p.RegisterResources(resources); err != nil {
		return nil, err
	}

	return p, nil
}