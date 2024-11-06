// sources/nginx_parser.go
package sources

import (
    "fmt"
    "regexp"
    "strconv"
    "strings"
    "time"

    "github.com/turbot/tailpipe-plugin-nginx/models"
)

// Standard NGINX combined log format regex
var nginxRegex = regexp.MustCompile(`^(?P<remote_addr>[^ ]*) (?P<remote_user>[^ ]*) (?P<user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<method>[A-Z]+)? ?(?P<uri>[^\"]*)" (?P<status>[^ ]*) (?P<bytes_sent>[^ ]*) "(?P<referer>[^\"]*)" "(?P<user_agent>[^\"]*)" (?P<server_name>[^ ]*)$`)

// ParseLogLine parses a single line of NGINX access log
func ParseLogLine(line string) (models.AccessLog, error) {
    matches := nginxRegex.FindStringSubmatch(line)
    if matches == nil {
        return models.AccessLog{}, fmt.Errorf("line does not match expected NGINX format: %s", line)
    }

    // Get the names of the capture groups
    names := nginxRegex.SubexpNames()
    
    // Create a map of field names to values
    fields := make(map[string]string)
    for i, match := range matches {
        if i != 0 && names[i] != "" {
            fields[names[i]] = match
        }
    }

    // Parse timestamp
    timeLocal, err := time.Parse("02/Jan/2006:15:04:05 -0700", fields["time_local"])
    if err != nil {
        return models.AccessLog{}, fmt.Errorf("error parsing time: %v", err)
    }

    // Parse status code
    status, err := strconv.Atoi(fields["status"])
    if err != nil {
        return models.AccessLog{}, fmt.Errorf("error parsing status code: %v", err)
    }

    // Parse bytes sent
    bytesSent := int64(0)
    if fields["bytes_sent"] != "-" {
        bytesSent, err = strconv.ParseInt(fields["bytes_sent"], 10, 64)
        if err != nil {
            return models.AccessLog{}, fmt.Errorf("error parsing bytes sent: %v", err)
        }
    }

    // Clean up user fields
    remoteUser := fields["remote_user"]
    if remoteUser == "-" {
        remoteUser = ""
    }

    // Split URI to get protocol
    uriParts := strings.Split(fields["uri"], " ")
    protocol := ""
    if len(uriParts) > 2 {
        protocol = uriParts[2]
    }

    // Build log entry
    logEntry := models.AccessLog{
        RemoteAddr:    fields["remote_addr"],
        RemoteUser:    remoteUser,
        TimeLocal:     timeLocal,
        Method:        fields["method"],
        URI:          fields["uri"],
        Protocol:     protocol,
        Status:       status,
        BytesSent:    bytesSent,
        Referer:      fields["referer"],
        UserAgent:    fields["user_agent"],
        ServerName:   fields["server_name"],
    }

    return logEntry, nil
}

// IsValidLogLine does a quick check if a line looks like a valid NGINX log entry
func IsValidLogLine(line string) bool {
    return nginxRegex.MatchString(line)
}