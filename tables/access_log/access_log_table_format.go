package access_log

import (
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

// Identifier returns the format TYPE
func (c *AccessLogTableFormat) Identifier() string {
	// format name is same as table name
	return AccessLogTableIdentifier
}

// GetName returns the format instance name
func (c *AccessLogTableFormat) GetName() string {
	// format name is same as table name
	return c.Name
}

func (c *AccessLogTableFormat) GetMapper() (mappers.Mapper[*types.DynamicRow], error) {
	// convert the layout to a regex
	regex, err := c.getRegex()
	if err != nil {
		return nil, err
	}
	return mappers.NewRegexMapper[*types.DynamicRow](regex)
}

// getRegex converts the layout to a regex
func (c *AccessLogTableFormat) getRegex() (string, error) {
	// TODO wire in grazas code
	return `TODO`, nil
}
