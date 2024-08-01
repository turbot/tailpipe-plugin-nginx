package nginx_source

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/satyrius/gonx"
	"github.com/turbot/tailpipe-plugin-nginx/nginx_types"
	"github.com/turbot/tailpipe-plugin-sdk/artifact"
)

type AccessLogMapper struct {
}

func NewAccessLogMapper() *AccessLogMapper {
	return &AccessLogMapper{}
}

func (c *AccessLogMapper) Identifier() string {
	return "access_log_mapper"
}

func (c *AccessLogMapper) Map(ctx context.Context, a *artifact.ArtifactData) ([]*artifact.ArtifactData, error) {
	var out []*artifact.ArtifactData

	// validate input type is string
	input, ok := a.Data.(string)
	if !ok {
		return nil, fmt.Errorf("expected string, got %T", a.Data)
	}

	inputMetadata := a.Metadata

	// TODO: #config - obtain this from config
	logFormat := `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
	// parse log line
	parser := gonx.NewParser(logFormat)
	parsed, err := parser.ParseString(input)
	if err != nil {
		return nil, fmt.Errorf("error parsing log line: %w", err)
	}

	// marshall Fields map to JSON
	fields := parsed.Fields()
	jsonBytes, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("error marshalling parsed fields: %w", err)
	}

	// unmarshall JSON to RawAccessLog
	var rawAccessLog nginx_types.RawAccessLog
	err = json.Unmarshal(jsonBytes, &rawAccessLog)
	if err != nil {
		return nil, fmt.Errorf("error decoding json to RawAccessLog: %w", err)
	}

	// return raw access log and metadata to be enriched
	out = append(out, artifact.NewData(rawAccessLog, artifact.WithMetadata(inputMetadata)))
	return out, nil
}

// TODO: #refactor - can we make this more generic and add it to the SDK?
