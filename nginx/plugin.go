package nginx

import (
	"github.com/turbot/tailpipe-plugin-nginx/nginx_collection"
	"github.com/turbot/tailpipe-plugin-sdk/collection"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
)

type Plugin struct {
	plugin.PluginBase
}

func NewPlugin() (plugin.TailpipePlugin, error) {
	p := &Plugin{}

	err := p.RegisterResources(
		&plugin.ResourceFunctions{
			Collections: []func() collection.Collection{nginx_collection.NewAccessLogCollection}, // TODO: #finish implement error log collection
		})
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (t *Plugin) Identifier() string {
	return "nginx"
}
