package nginx

import (
	"github.com/turbot/tailpipe-plugin-nginx/nginx_collection"
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/plugin"
)

type Plugin struct {
	plugin.Base
}

func NewPlugin() (plugin.TailpipePlugin, error) {
	p := &Plugin{}

	time.Sleep(10 * time.Second) // TODO: #debug remove this startup delay

	// register collections which we support
	err := p.RegisterCollections(nginx_collection.NewAccessLogCollection)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (t *Plugin) Identifier() string {
	return "nginx"
}
