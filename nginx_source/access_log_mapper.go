package nginx_source

import (
	"context"
	"fmt"

	"github.com/satyrius/gonx"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_mapper"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

type AccessLogMapper struct {
	logFormat string
}

func NewAccessLogMapper(logFormat string) artifact_mapper.Mapper {
	return &AccessLogMapper{
		logFormat: logFormat,
	}
}

func (c *AccessLogMapper) Identifier() string {
	return "access_log_mapper"
}

func (c *AccessLogMapper) Map(ctx context.Context, a *types.RowData) ([]*types.RowData, error) {
	var out []*types.RowData

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
	out = append(out, types.NewData(fields, types.WithMetadata(inputMetadata)))

	return out, nil
}

// TODO: #refactor - can we make this more generic and add it to the SDK?
