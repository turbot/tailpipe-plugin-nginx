package access_log

import (
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/formats"
	"github.com/turbot/tailpipe-plugin-sdk/mappers"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

type AccessLogTableFormat struct {
	// the name of this format instance
	Name string `hcl:"name,label"`
	// the layout of the log line
	// NOTE that as will contain grok patterns, this property is included in constants.GrokConfigProperties
	// meaning and '{' will be auto-escaped in the hcl
	Layout string `hcl:"layout"`
}

func NewAccessLogTableFormat() formats.Format {
	return &AccessLogTableFormat{}
}

func (c *AccessLogTableFormat) Validate() error {
	return nil
}

func (c *AccessLogTableFormat) Identifier() string {
	return constants.SourceFormatRegex
}

func (c *AccessLogTableFormat) GetMapper() (mappers.Mapper[*types.DynamicRow], error) {
	regex, err := c.getRegex()
	if err != nil {
		return nil, err
	}
	return mappers.NewRegexMapper[*types.DynamicRow](regex)
}

func (c *AccessLogTableFormat) getRegex() (string, error) {
	// TODO wire in grazas code
	return `TODO`, nil
}
