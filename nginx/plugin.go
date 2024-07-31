package nginx

import (
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
	err := p.RegisterCollections() // TODO: #finish register collections
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (t *Plugin) Identifier() string {
	return "nginx"
}
