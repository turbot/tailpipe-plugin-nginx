package nginx_collection

type AccessLogCollectionConfig struct {
	Paths     []string
	LogFormat *string
}
