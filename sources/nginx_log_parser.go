// sources/nginx_log_parser.go
package sources

import (
    "fmt"
    "regexp"
    "strconv"
    "strings"
    "time"
    "log/slog"

    "github.com/turbot/tailpipe-plugin-nginx/models"
)

var nginxRegex = regexp.MustCompile(`^(?P<remote_addr>[^ ]+) (?P<remote_user>[^ ]+) (?P<local_user>[^ ]+) \[(?P<time_local>[^\]]+)\] "(?P<method>[A-Z]+) (?P<uri>[^ ]+) HTTP/(?P<http_version>[^ ]+)" (?P<status>\d{3}) (?P<bytes_sent>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"`)

// IsValidLogLine performs a quick check if a line looks like a valid NGINX log entry
func IsValidLogLine(line string) bool {
    // Check for basic structure elements
    if !strings.Contains(line, " [") || !strings.Contains(line, "] \"") {
        slog.Debug("Basic structure check failed", "line", line)
        return false
    }
    
    // Split the line on the timestamp section to handle the rest
    parts := strings.SplitN(line, "] \"", 2)
    if len(parts) != 2 {
        slog.Debug("Failed to split on timestamp", "parts_count", len(parts))
        return false
    }

    // Extract the request section and the rest
    requestAndRest := parts[1]
    requestParts := strings.SplitN(requestAndRest, "\" ", 2)
    if len(requestParts) != 2 {
        slog.Debug("Failed to split request section", "parts_count", len(requestParts))
        return false
    }

    // Parse the status and bytes section
    statusAndRest := requestParts[1]
    statusParts := strings.Fields(statusAndRest)
    if len(statusParts) < 2 {
        slog.Debug("Status parts check failed", "parts_count", len(statusParts))
        return false
    }

    // Verify status code is 3 digits
    if !regexp.MustCompile(`^\d{3}$`).MatchString(statusParts[0]) {
        slog.Debug("Status code format check failed", "status", statusParts[0])
        return false
    }

    // Verify bytes sent is numeric
    if !regexp.MustCompile(`^\d+$`).MatchString(statusParts[1]) {
        slog.Debug("Bytes sent format check failed", "bytes", statusParts[1])
        return false
    }

    return true
}

// ParseLogLine parses a single line of NGINX access log
func ParseLogLine(line string) (models.AccessLog, error) {
    slog.Debug("Parsing log line", "line", line)

    // Quick validation before expensive regex
    if !IsValidLogLine(line) {
        slog.Error("Invalid log line format", "line", line)
        return models.AccessLog{}, fmt.Errorf("invalid log line format: %s", line)
    }

    matches := nginxRegex.FindStringSubmatch(line)
    if matches == nil {
        slog.Error("Line does not match NGINX format", "line", line)
        return models.AccessLog{}, fmt.Errorf("line does not match NGINX format: %s", line)
    }

    // Get the names of the capture groups
    names := nginxRegex.SubexpNames()
    
    // Create a map of field names to values
    fields := make(map[string]string)
    for i, match := range matches {
        if i != 0 && names[i] != "" {
            fields[names[i]] = match
            slog.Debug("Captured field", "name", names[i], "value", match)
        }
    }

    // Parse timestamp
    timeLocal, err := time.Parse("02/Jan/2006:15:04:05 -0700", fields["time_local"])
    if err != nil {
        slog.Error("Error parsing timestamp", "time_str", fields["time_local"], "error", err)
        return models.AccessLog{}, fmt.Errorf("error parsing timestamp: %v", err)
    }

    // Parse status code
    status, err := strconv.Atoi(fields["status"])
    if err != nil {
        slog.Error("Error parsing status code", "status", fields["status"], "error", err)
        return models.AccessLog{}, fmt.Errorf("error parsing status code: %v", err)
    }

    // Parse bytes sent
    bytesSent, err := strconv.ParseInt(fields["bytes_sent"], 10, 64)
    if err != nil {
        slog.Error("Error parsing bytes sent", "bytes", fields["bytes_sent"], "error", err)
        return models.AccessLog{}, fmt.Errorf("error parsing bytes sent: %v", err)
    }

    // Clean up user fields
    remoteUser := fields["remote_user"]
    if remoteUser == "-" {
        remoteUser = ""
    }

    // Build log entry
    logEntry := models.AccessLog{
        RemoteAddr:    fields["remote_addr"],
        RemoteUser:    remoteUser,
        TimeLocal:     timeLocal,
        Method:        fields["method"],
        URI:          fields["uri"],
        Protocol:     "HTTP/" + fields["http_version"],
        Status:       status,
        BytesSent:    bytesSent,
        Referer:      fields["referer"],
        UserAgent:    fields["user_agent"],
        ServerName:   "default", // Since server name isn't in the log format
    }

    slog.Debug("Successfully parsed log entry", 
        "remote_addr", logEntry.RemoteAddr,
        "method", logEntry.Method,
        "uri", logEntry.URI,
        "status", logEntry.Status)

    return logEntry, nil
}