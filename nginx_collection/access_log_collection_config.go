package nginx_collection

type AccessLogCollectionConfig struct {
	LogFormat *string `hcl:"log_format"`
}

func (a AccessLogCollectionConfig) Validate() error {
	//TODO #graza implement me
	return nil
}
