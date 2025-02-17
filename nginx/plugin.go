package nginx

import (
	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/tailpipe-plugin-nginx/tables/access_log"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const PluginName = "nginx"

func init() {
	// Register the table, with type parameters:
	// 1. row struct type
	// 2. table implementation type
	// And function parameters:
	// 1. table definition
	// 2. format
	table.RegisterCustomTable[*table.DynamicRow, *access_log.AccessLogTable](access_log.AccessLogTableDef, access_log.AccessLogFormat)
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
