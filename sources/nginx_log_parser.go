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

// Updated regex to match standard NGINX log format including double quotes and optional HTTP version
var nginxRegex = regexp.MustCompile(`^(?P<remote_addr>[^ ]*) (?P<remote_user>[^ ]*) (?P<user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?:(?P<method>[^ ]*) (?P<uri>[^ ]*)(?: HTTP/[0-9.]+)?|[^"]*)" (?P<status>[0-9]*) (?P<bytes_sent>[0-9-]*) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"`)

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
    status := 0
    if fields["status"] != "" {
        status, err = strconv.Atoi(fields["status"])
        if err != nil {
            return models.AccessLog{}, fmt.Errorf("error parsing status code: %v", err)
        }
    }

    // Parse bytes sent
    bytesSent := int64(0)
    if fields["bytes_sent"] != "" && fields["bytes_sent"] != "-" {
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

    // Extract protocol from request
    protocol := ""
    if strings.Contains(fields["uri"], " HTTP/") {
        parts := strings.Split(fields["uri"], " ")
        if len(parts) > 1 {
            protocol = parts[len(parts)-1]
        }
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
        ServerName:   "default", // Since server name isn't in the log format
    }

    return logEntry, nil
}

// IsValidLogLine does a quick check if a line looks like a valid NGINX log entry
func IsValidLogLine(line string) bool {
    return nginxRegex.MatchString(line)
}