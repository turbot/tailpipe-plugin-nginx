// sources/access_log_file_source.go
package sources

import (
    "bufio"
    "context"
    "fmt"
    "os"
    "path/filepath"
    "log/slog"

    "github.com/turbot/tailpipe-plugin-sdk/enrichment"
    "github.com/turbot/tailpipe-plugin-sdk/row_source"
    "github.com/turbot/tailpipe-plugin-sdk/types"
    "github.com/turbot/tailpipe-plugin-sdk/parse"
)

const AccessLogFileSourceIdentifier = "nginx_access_log_file"

type AccessLogFileSource struct {
    row_source.RowSourceBase[*AccessLogFileSourceConfig]
}

func NewAccessLogFileSource() row_source.RowSource {
    return &AccessLogFileSource{}
}

func (s *AccessLogFileSource) Identifier() string {
    return AccessLogFileSourceIdentifier
}

func (s *AccessLogFileSource) GetConfigSchema() parse.Config {
    return &AccessLogFileSourceConfig{}
}

func (s *AccessLogFileSource) Collect(ctx context.Context) error {
    logPath := s.Config.LogPath

    // Check if path exists
    _, err := os.Stat(logPath)
    if err != nil {
        return fmt.Errorf("error accessing log path: %v", err)
    }

    // If it's a directory and we have a pattern, use filepath.Walk
    if info, _ := os.Stat(logPath); info.IsDir() && s.Config.FilePattern != "" {
        return filepath.Walk(logPath, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }
            matched, err := filepath.Match(s.Config.FilePattern, info.Name())
            if err != nil {
                return err
            }
            if !info.IsDir() && matched {
                if err := s.processFile(ctx, path); err != nil {
                    slog.Error("Error processing file", "path", path, "error", err)
                }
            }
            return nil
        })
    }

    // Otherwise, process single file
    return s.processFile(ctx, logPath)
}

func (s *AccessLogFileSource) processFile(ctx context.Context, filePath string) error {
    file, err := os.Open(filePath)
    if err != nil {
        return fmt.Errorf("error opening file: %v", err)
    }
    defer file.Close()

    sourceEnrichmentFields := &enrichment.CommonFields{
        TpSourceName:     AccessLogFileSourceIdentifier,
        TpSourceType:     "nginx_access_log",
        TpSourceLocation: &filePath,
    }

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()

        if !IsValidLogLine(line) {
            slog.Debug("Skipping invalid log line", "line", line)
            continue
        }

        logEntry, err := ParseLogLine(line)
        if err != nil {
            slog.Error("Error parsing log line", "line", line, "error", err)
            continue
        }

        // Create row data with the value
        row := &types.RowData{
            Data:     logEntry,  // Note: using the value directly
            Metadata: sourceEnrichmentFields,
        }

        if err := s.OnRow(ctx, row, nil); err != nil {
            return fmt.Errorf("error processing row: %w", err)
        }
    }

    if err := scanner.Err(); err != nil {
        return fmt.Errorf("error reading file: %v", err)
    }

    return nil
}