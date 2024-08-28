package nginx_partition

type AccessLogPartitionConfig struct {
	LogFormat *string `hcl:"log_format"`
}

func (a *AccessLogPartitionConfig) Validate() error {
	//TODO #graza implement me
	return nil
}
