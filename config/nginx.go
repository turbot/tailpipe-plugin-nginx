package config

import "github.com/turbot/tailpipe-plugin-sdk/parse"

type NginxConnection struct {
}

func NewNginxConnection() parse.Config {
	return &NginxConnection{}
}

func (c *NginxConnection) Validate() error {
	return nil
}
