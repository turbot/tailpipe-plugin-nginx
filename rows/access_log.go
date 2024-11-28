package rows

import (
	"strconv"
	"strings"
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
)

type AccessLog struct {
	enrichment.CommonFields

	RemoteAddr     *string         `json:"remote_addr,omitempty"`
	RemoteUser     *string         `json:"remote_user,omitempty"`
	TimeLocal      *string         `json:"time_local,omitempty"`
	TimeIso8601    *string         `json:"time_iso8601,omitempty"`
	Request        *string         `json:"request,omitempty"`
	RequestDetails *RequestDetails `json:"request_details,omitempty"`
	Method         *string         `json:"method,omitempty"`
	Path           *string         `json:"path,omitempty"`
	HttpVersion    *string         `json:"http_version,omitempty"`
	Status         *int            `json:"status,omitempty"`
	BodyBytesSent  *int            `json:"body_bytes_sent,omitempty"`
	HttpReferer    *string         `json:"http_referer,omitempty"`
	HttpUserAgent  *string         `json:"http_user_agent,omitempty"`
	Timestamp      *time.Time      `json:"timestamp,omitempty"`
}

type RequestDetails struct {
	Method       *string           `json:"method,omitempty"`
	Path         *string           `json:"path,omitempty"`
	HttpVersion  *string           `json:"http_version,omitempty"`
	QueryParams  map[string]string `json:"query_params,omitempty"`
	PathSegments []string          `json:"path_segments,omitempty"`
	Extension    *string           `json:"extension,omitempty"`
}

func NewAccessLog() *AccessLog {
	return &AccessLog{}
}

func (l *AccessLog) InitialiseFromMap(m map[string]string) error {
	for key, value := range m {
		switch key {
		case "remote_addr":
			l.RemoteAddr = &value
			l.TpSourceIP = &value
			l.TpIps = append(l.TpIps, value)
		case "remote_user":
			l.RemoteUser = &value
			if value != "" && value != "-" {
				l.TpUsernames = append(l.TpUsernames, value)
			}
		case "time_local":
			l.TimeLocal = &value
			t, err := time.Parse("02/Jan/2006:15:04:05 -0700", value)
			if err != nil {
				return err
			}
			iso := t.Format(time.RFC3339)
			l.TimeIso8601 = &iso
			l.Timestamp = &t
		case "time_iso8601":
			l.TimeIso8601 = &value
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return err
			}
			l.Timestamp = &t
		case "request":
			l.Request = &value
			// Split "GET /login HTTP/1.1" into components
			parts := strings.SplitN(value, " ", 3)
			if len(parts) == 3 {
				method := parts[0]
				path := parts[1]
				version := strings.TrimPrefix(parts[2], "HTTP/")

				// Set the individual fields
				l.Method = &method
				l.Path = &path
				l.HttpVersion = &version

				// Parse path segments
				var segments []string
				trimmedPath := strings.Trim(path, "/")
				if trimmedPath == "" {
					segments = []string{"/"} // Special case for root path
				} else {
					segments = strings.Split(trimmedPath, "/")
				}

				// Parse query parameters
				queryParams := make(map[string]string)
				if idx := strings.Index(path, "?"); idx != -1 {
					query := path[idx+1:]
					path = path[:idx]
					for _, param := range strings.Split(query, "&") {
						if kv := strings.SplitN(param, "=", 2); len(kv) == 2 {
							queryParams[kv[0]] = kv[1]
						}
					}
				}

				// Get file extension if present
				var extension *string
				if len(segments) > 0 && segments[len(segments)-1] != "/" {
					if lastSegment := segments[len(segments)-1]; strings.Contains(lastSegment, ".") {
						if ext := strings.Split(lastSegment, "."); len(ext) > 1 {
							ext := ext[len(ext)-1]
							extension = &ext
						}
					}
				}

				// Populate RequestDetails
				l.RequestDetails = &RequestDetails{
					Method:       &method,
					Path:         &path,
					HttpVersion:  &version,
					QueryParams:  queryParams,
					PathSegments: segments,
					Extension:    extension,
				}
			}
		case "status":
			status, err := strconv.Atoi(value)
			if err != nil {
				return err
			}
			l.Status = &status
		case "body_bytes_sent":
			bbs, err := strconv.Atoi(value)
			if err != nil {
				return err
			}
			l.BodyBytesSent = &bbs
		case "http_referer":
			l.HttpReferer = &value
		case "http_user_agent":
			l.HttpUserAgent = &value
		}
	}
	return nil
}
