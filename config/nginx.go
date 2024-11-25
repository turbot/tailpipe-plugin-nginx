package config

const PluginName = "nginx"

type NginxConnection struct {
}

func (c *NginxConnection) Validate() error {
	return nil
}

func (c *NginxConnection) Identifier() string {
	return PluginName
}
