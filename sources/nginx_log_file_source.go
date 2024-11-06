package sources

import (
    "bufio"
    "context"
    "fmt"
    "os"
    "path/filepath"
    "time"
    "log/slog"

    "github.com/turbot/tailpipe-plugin-sdk/collection_state"
    "github.com/turbot/tailpipe-plugin-sdk/enrichment"
    "github.com/turbot/tailpipe-plugin-sdk/row_source"
    "github.com/turbot/tailpipe-plugin-sdk/types"
    "github.com/turbot/tailpipe-plugin-sdk/parse"
)

const AccessLogFileSourceIdentifier = "nginx_access_log_file"

type AccessLogFileSource struct {
    row_source.RowSourceImpl[*AccessLogFileSourceConfig]
}

func NewAccessLogFileSource() row_source.RowSource {
    return &AccessLogFileSource{}
}

func (s *AccessLogFileSource) Init(ctx context.Context, configData *types.ConfigData, opts ...row_source.RowSourceOption) error {
    // set the collection state ctor
    s.NewCollectionStateFunc = collection_state.NewTimeRangeCollectionState

    // call base init
    return s.RowSourceImpl.Init(ctx, configData, opts...)
}

func (s *AccessLogFileSource) Identifier() string {
    return AccessLogFileSourceIdentifier
}

func (s *AccessLogFileSource) GetConfigSchema() parse.Config {
    return &AccessLogFileSourceConfig{}
}

func (s *AccessLogFileSource) Collect(ctx context.Context) error {
    collectionState := s.CollectionState.(*collection_state.TimeRangeCollectionState[*AccessLogFileSourceConfig])
    collectionState.StartCollection()
    defer collectionState.EndCollection()

    logPath := s.Config.LogPath
    
    // Check if path exists
    info, err := os.Stat(logPath)
    if err != nil {
        return fmt.Errorf("error accessing log path: %v", err)
    }

    // Load timezone location
    location := time.UTC
    if s.Config.Timezone != "" {
        location, err = time.LoadLocation(s.Config.Timezone)
        if err != nil {
            return fmt.Errorf("invalid timezone: %v", err)
        }
    }

    // If it's a directory and we have a pattern, use filepath.Walk
    if info.IsDir() && s.Config.FilePattern != "" {
        err = filepath.Walk(logPath, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }
            matched, err := filepath.Match(s.Config.FilePattern, info.Name())
            if err != nil {
                return err
            }
            if !info.IsDir() && matched {
                if err := s.processFile(ctx, path, location, collectionState); err != nil {
                    slog.Error("Error processing file", "path", path, "error", err)
                }
            }
            return nil
        })
        if err != nil {
            return fmt.Errorf("error walking directory: %v", err)
        }
    } else {
        // Process single file
        err = s.processFile(ctx, logPath, location, collectionState)
        if err != nil {
            return fmt.Errorf("error processing file %s: %v", logPath, err)
        }
    }

    return nil
}

func (s *AccessLogFileSource) processFile(ctx context.Context, filePath string, location *time.Location, collectionState *collection_state.TimeRangeCollectionState[*AccessLogFileSourceConfig]) error {
    file, err := os.Open(filePath)
    if err != nil {
        return fmt.Errorf("error opening file: %v", err)
    }
    defer file.Close()

    // Set up source enrichment fields
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

        // Apply timezone and server name from config if set
        logEntry.TimeLocal = logEntry.TimeLocal.In(location)
        if s.Config.ServerName != "" {
            logEntry.ServerName = s.Config.ServerName
        }

        // Check if we should collect this row based on time
        if !collectionState.ShouldCollectRow(logEntry.TimeLocal, logEntry.URI) {
            continue
        }

        // Create row data with the value
        row := &types.RowData{
            Data:     &logEntry,
            Metadata: sourceEnrichmentFields,
        }

        // Update collection state
        collectionState.Upsert(logEntry.TimeLocal, logEntry.URI, nil)
        
        // Get collection state as JSON
        collectionStateJSON, err := s.GetCollectionStateJSON()
        if err != nil {
            return fmt.Errorf("error serializing collection state: %v", err)
        }

        if err := s.OnRow(ctx, row, collectionStateJSON); err != nil {
            return fmt.Errorf("error processing row: %w", err)
        }
    }

    if err := scanner.Err(); err != nil {
        return fmt.Errorf("error reading file: %v", err)
    }

    return nil
}