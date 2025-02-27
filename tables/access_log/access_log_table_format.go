package access_log

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

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
	format := c.Layout
	var unknownTokens []string

	// escape brackets
	format = strings.ReplaceAll(format, "[", `\[`)
	format = strings.ReplaceAll(format, "]", `\]`)
	format = strings.ReplaceAll(format, "(", `\(`)
	format = strings.ReplaceAll(format, ")", `\)`)

	// Replace tokens with regex patterns
	re := regexp.MustCompile(`\$\w+`)
	format = re.ReplaceAllStringFunc(format, func(match string) string {
		if pattern, exists := getRegexForSegment(match); exists {
			return pattern
		} else {
			unknownTokens = append(unknownTokens, match)
		}

		return match
	})

	if len(unknownTokens) > 0 {
		return "", errors.New("unknown tokens in format: " + strings.Join(unknownTokens, ", "))
	}

	if len(format) > 0 {
		format = fmt.Sprintf("^%s", format)
	}

	return format, nil
}

func getRegexForSegment(segment string) (string, bool) {
	const defaultRegexFormat = `(?P<%s>[^ ]*)`

	if _, exists := getValidNginxTokenMap()[segment]; !exists {
		return segment, false
	}

	if override, isOverridden := getRegexOverrides()[segment]; isOverridden {
		return override, true
	}

	return fmt.Sprintf(defaultRegexFormat, strings.TrimPrefix(segment, "$")), true
}

func getValidNginxTokenMap() map[string]struct{} {
	return map[string]struct{}{
		`$remote_addr`:            {},
		`$host`:                   {},
		`$remote_user`:            {},
		`$time_local`:             {},
		`$request`:                {},
		`$request_method`:         {},
		`$request_uri`:            {},
		`$server_protocol`:        {},
		`$status`:                 {},
		`$body_bytes_sent`:        {},
		`$http_referer`:           {},
		`$http_user_agent`:        {},
		`$scheme`:                 {},
		`$http_host`:              {},
		`$http_cookie`:            {},
		`$content_length`:         {},
		`$content_type`:           {},
		`$request_length`:         {},
		`$server_name`:            {},
		`$server_addr`:            {},
		`$server_port`:            {},
		`$connection`:             {},
		`$connection_requests`:    {},
		`$msec`:                   {},
		`$time_iso8601`:           {},
		`$bytes_sent`:             {},
		`$request_time`:           {},
		`$pipe`:                   {},
		`$upstream_addr`:          {},
		`$upstream_status`:        {},
		`$upstream_response_time`: {},
		`$upstream_connect_time`:  {},
		`$upstream_header_time`:   {},
		`$ssl_protocol`:           {},
		`$ssl_cipher`:             {},
		`$ssl_session_id`:         {},
		`$ssl_client_cert`:        {},
		`$ssl_session_reused`:     {},
		`$gzip_ratio`:             {},
	}
}

func getRegexOverrides() map[string]string {
	return map[string]string{
		`$time_local`:      `(?P<time_local>[^\]]*)`,
		`$request`:         `(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?`,
		`$request_method`:  `(?P<request_method>\S+)`,
		`$request_uri`:     `(?P<request_uri>.*?)`,
		`$server_protocol`: `(?P<server_protocol>\S+)`,
		`$http_referer`:    `(?P<http_referer>.*?)`,
		`$http_user_agent`: `(?P<http_user_agent>.*?)`,
	}
}
