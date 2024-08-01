package nginx_source

import (
	"context"
	"fmt"

	"github.com/satyrius/gonx"
	"github.com/turbot/tailpipe-plugin-sdk/artifact"
)

type AccessLogMapper struct {
	logFormat string
}

func NewAccessLogMapper(logFormat string) *AccessLogMapper {
	return &AccessLogMapper{
		logFormat: logFormat,
	}
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

	// parse log line
	parser := gonx.NewParser(c.logFormat)
	parsed, err := parser.ParseString(input)
	if err != nil {
		return nil, fmt.Errorf("error parsing log line: %w", err)
	}

	fields := make(map[string]string)

	fields = parsed.Fields()
	out = append(out, artifact.NewData(fields, artifact.WithMetadata(inputMetadata)))

	return out, nil
}

// TODO: #refactor - can we make this more generic and add it to the SDK?
