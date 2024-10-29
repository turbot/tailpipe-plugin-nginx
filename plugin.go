package main

import (
	"github.com/turbot/tailpipe-plugin-nginx/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

// NewPlugin returns a new instance of a [plugin.TailpipePlugin]
func NewPlugin() (plugin.TailpipePlugin, error) {
	p := plugin.NewPlugin("nginx")

	err := p.RegisterResources(
		&plugin.ResourceFunctions{
			Tables: []func() table.Table{tables.NewAccessLogCollection},
		})
	if err != nil {
		return nil, err
	}

	return p, nil
}
