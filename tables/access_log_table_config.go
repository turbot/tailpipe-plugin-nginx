package tables

type AccessLogTableConfig struct {
	LogFormat *string `hcl:"log_format"`
}

func (a *AccessLogTableConfig) Validate() error {
	//TODO #graza implement me
	return nil
}
