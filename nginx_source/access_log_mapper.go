package nginx_source

import (
	"context"
	"log/slog"
	"reflect"

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
	// NOTE: a.Data = Raw log line as a interface{} | string with a nil value for metadata
	slog.Log(ctx, slog.LevelInfo, "AccessLogMapper", "received", a, "type", reflect.TypeOf(a))

	return out, nil

}
