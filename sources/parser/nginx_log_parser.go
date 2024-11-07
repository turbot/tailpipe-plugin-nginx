// sources/parser.go
package sources

import (
    "fmt"
    "regexp"
    "strconv"
    "strings"
    "time"

    "github.com/turbot/tailpipe-plugin-nginx/models"
    "log/slog"
)

// Updated regex to match standard NGINX log format, including optional HTTP version
var nginxRegex = regexp.MustCompile(`^(?P<remote_addr>[^ ]*) (?P<remote_user>[^ ]*) (?P<user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?:(?P<method>[^ ]*) (?P<uri>[^ ]*)(?: HTTP/[0-9.]+)?|[^"]*)" (?P<status>[0-9]*) (?P<bytes_sent>[0-9-]*) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"`)

// ParseLogLine parses a single line of NGINX access log with detailed debug logging
func ParseLogLine(line string) (models.AccessLog, error) {
    slog.Info("Parsing log line", "line", line)

    // Attempt to match the line with the regex
    matches := nginxRegex.FindStringSubmatch(line)
    if matches == nil {
        slog.Error("Line does not match expected NGINX format", "line", line)
        return models.AccessLog{}, fmt.Errorf("line does not match expected NGINX format: %s", line)
    }

    // Capture the names of the groups for better debugging
    names := nginxRegex.SubexpNames()
    fields := make(map[string]string)

    // Populate the fields map and log each captured group
    for i, match := range matches {
        if i != 0 && names[i] != "" { // Skip the full match
            fields[names[i]] = match
            slog.Debug("Captured field", "name", names[i], "value", match)
        }
    }

    // Parse timestamp
    timeLocal, err := time.Parse("02/Jan/2006:15:04:05 -0700", fields["time_local"])
    if err != nil {
        slog.Error("Error parsing timestamp", "time_local", fields["time_local"], "error", err)
        return models.AccessLog{}, fmt.Errorf("error parsing time: %v", err)
    }

    // Parse status code
    status := 0
    if fields["status"] != "" {
        status, err = strconv.Atoi(fields["status"])
        if err != nil {
            slog.Error("Error parsing status code", "status", fields["status"], "error", err)
            return models.AccessLog{}, fmt.Errorf("error parsing status code: %v", err)
        }
    }

    // Parse bytes sent
    bytesSent := int64(0)
    if fields["bytes_sent"] != "" && fields["bytes_sent"] != "-" {
        bytesSent, err = strconv.ParseInt(fields["bytes_sent"], 10, 64)
        if err != nil {
            slog.Error("Error parsing bytes sent", "bytes_sent", fields["bytes_sent"], "error", err)
            return models.AccessLog{}, fmt.Errorf("error parsing bytes sent: %v", err)
        }
    }

    // Process remote user
    remoteUser := fields["remote_user"]
    if remoteUser == "-" {
        remoteUser = ""
    }

    // Extract protocol from request (optional field)
    protocol := ""
    uri := fields["uri"]
    if strings.Contains(uri, " HTTP/") {
        parts := strings.SplitN(uri, " HTTP/", 2)
        if len(parts) == 2 {
            uri = parts[0]         // Update URI to exclude protocol
            protocol = "HTTP/" + parts[1]
            slog.Debug("Extracted protocol", "protocol", protocol)
        }
    }

    // Build log entry and log the final structured entry
    logEntry := models.AccessLog{
        RemoteAddr:    fields["remote_addr"],
        RemoteUser:    remoteUser,
        TimeLocal:     timeLocal,
        Method:        fields["method"],
        URI:           uri,       // Use cleaned-up URI
        Protocol:      protocol,  // Only if HTTP version is present
        Status:        status,
        BytesSent:     bytesSent,
        Referer:       fields["referer"],
        UserAgent:     fields["user_agent"],
        ServerName:    "default", // Default since server name isn't in log format
    }

    slog.Info("Parsed log entry successfully", "logEntry", logEntry)
    return logEntry, nil
}

// IsValidLogLine does a quick check if a line looks like a valid NGINX log entry
func IsValidLogLine(line string) bool {
    // Optional quick pre-validation using simple markers to improve performance
    return strings.Contains(line, "[") && strings.Contains(line, "] \"") && strings.Contains(line, "\" ")
}
