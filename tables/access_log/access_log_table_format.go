package access_log

import (
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
	// Description of the format
	Description string `hcl:"description,optional"`
	// the layout of the log line
	Layout string `hcl:"layout"`
}

func NewAccessLogTableFormat() formats.Format {
	return &AccessLogTableFormat{}
}

func (a *AccessLogTableFormat) Validate() error {
	return nil
}

// Identifier returns the format TYPE
func (a *AccessLogTableFormat) Identifier() string {
	// format name is same as table name
	return AccessLogTableIdentifier
}

// GetName returns the format instance name
func (a *AccessLogTableFormat) GetName() string {
	// format name is same as table name
	return a.Name
}

// SetName sets the name of this format instance
func (a *AccessLogTableFormat) SetName(name string) {
	a.Name = name
}

func (a *AccessLogTableFormat) GetDescription() string {
	return a.Description
}

func (a *AccessLogTableFormat) GetMapper() (mappers.Mapper[*types.DynamicRow], error) {
	// convert the layout to a regex
	regex, err := a.GetRegex()
	if err != nil {
		return nil, err
	}
	return mappers.NewRegexMapper[*types.DynamicRow](regex)
}

func (a *AccessLogTableFormat) GetRegex() (string, error) {
	format := regexp.QuoteMeta(a.Layout)
	var unsupportedTokens []string

	// regex to grab tokens
	re := regexp.MustCompile(`\\\$\w+`)

	// check for concatenated tokens (e.g. $body_bytes$status)
	tokens := re.FindAllStringIndex(format, -1)
	for i := 1; i < len(tokens); i++ {
		// With QuoteMeta, tokens will be 2 characters further apart due to the backslash escape
		if tokens[i][0]-tokens[i-1][1] < 1 {
			return "", fmt.Errorf("concatenated tokens detected in format '%s', this is currently unsupported in this format, if this is a requirement a Regex format can be used", a.Layout)
		}
	}

	// replace tokens with regex patterns
	format = re.ReplaceAllStringFunc(format, func(match string) string {
		if pattern, exists := getRegexForSegment(match); exists {
			return pattern
		} else {
			unsupportedTokens = append(unsupportedTokens, strings.TrimPrefix(match, `\`))
		}

		return match
	})

	if len(unsupportedTokens) > 0 {
		return "", fmt.Errorf("the following tokens are not currently supported in this format: %s", strings.Join(unsupportedTokens, ", "))
	}

	if len(format) > 0 {
		format = fmt.Sprintf("^%s", format)
	}

	return format, nil
}

func (a *AccessLogTableFormat) GetProperties() map[string]string {
	return map[string]string{
		"layout": a.Layout,
	}
}

func getRegexForSegment(segment string) (string, bool) {
	const defaultRegexFormat = `(?P<%s>[^ ]*)`

	if _, exists := getValidNginxTokenMap()[segment]; !exists {
		return segment, false
	}

	if override, isOverridden := getRegexOverrides()[segment]; isOverridden {
		return override, true
	}

	return fmt.Sprintf(defaultRegexFormat, strings.TrimPrefix(segment, `\$`)), true
}

func getValidNginxTokenMap() map[string]struct{} {
	return map[string]struct{}{
		`\$remote_addr`:            {},
		`\$host`:                   {},
		`\$remote_user`:            {},
		`\$time_local`:             {},
		`\$request`:                {},
		`\$request_method`:         {},
		`\$request_uri`:            {},
		`\$server_protocol`:        {},
		`\$status`:                 {},
		`\$body_bytes_sent`:        {},
		`\$http_referer`:           {},
		`\$http_user_agent`:        {},
		`\$scheme`:                 {},
		`\$http_host`:              {},
		`\$http_cookie`:            {},
		`\$content_length`:         {},
		`\$content_type`:           {},
		`\$request_length`:         {},
		`\$server_name`:            {},
		`\$server_addr`:            {},
		`\$server_port`:            {},
		`\$connection`:             {},
		`\$connection_requests`:    {},
		`\$msec`:                   {},
		`\$time_iso8601`:           {},
		`\$bytes_sent`:             {},
		`\$request_time`:           {},
		`\$pipe`:                   {},
		`\$upstream_addr`:          {},
		`\$upstream_status`:        {},
		`\$upstream_response_time`: {},
		`\$upstream_connect_time`:  {},
		`\$upstream_header_time`:   {},
		`\$ssl_protocol`:           {},
		`\$ssl_cipher`:             {},
		`\$ssl_session_id`:         {},
		`\$ssl_client_cert`:        {},
		`\$ssl_session_reused`:     {},
		`\$gzip_ratio`:             {},
	}
}

func getRegexOverrides() map[string]string {
	return map[string]string{
		`\$time_local`:      `(?P<time_local>[^\]]*)`,
		`\$request`:         `(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?`,
		`\$request_method`:  `(?P<request_method>\S+)`,
		`\$request_uri`:     `(?P<request_uri>.*?)`,
		`\$server_protocol`: `(?P<server_protocol>\S+)`,
		`\$http_referer`:    `(?P<http_referer>.*?)`,
		`\$http_user_agent`: `(?P<http_user_agent>.*?)`,
	}
}
