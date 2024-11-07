// sources/nginx_log_file_source.go
package sources

import (
    "bufio"
    "context"
    "encoding/json"
    "fmt"
    "os"
    "time"
    "log/slog"

    "github.com/turbot/tailpipe-plugin-sdk/collection_state"
    "github.com/turbot/tailpipe-plugin-sdk/enrichment"
    "github.com/turbot/tailpipe-plugin-sdk/parse"
    "github.com/turbot/tailpipe-plugin-sdk/row_source"
    "github.com/turbot/tailpipe-plugin-sdk/types"
    "github.com/turbot/tailpipe-plugin-sdk/config_data"
)

const AccessLogFileSourceIdentifier = "nginx_access_log_file"

type AccessLogFileSource struct {
    row_source.RowSourceImpl[*AccessLogFileSourceConfig]
}

// TimeRange represents a time range in the collection state
type TimeRange struct {
    StartTime time.Time              `json:"start_time"`
    EndTime   time.Time              `json:"end_time"`
    StartIds  map[string]interface{} `json:"start_identifiers"`
    EndIds    map[string]interface{} `json:"end_identifiers"`
}

// CollectionState represents the structure of our collection state JSON
type CollectionState struct {
    Ranges []TimeRange `json:"ranges"`
}

func NewAccessLogFileSource() row_source.RowSource {
    return &AccessLogFileSource{}
}

func (s *AccessLogFileSource) Identifier() string {
    return AccessLogFileSourceIdentifier
}

func (s *AccessLogFileSource) Init(ctx context.Context, configData config_data.ConfigData, opts ...row_source.RowSourceOption) error {
    // set the collection state ctor
    s.NewCollectionStateFunc = collection_state.NewTimeRangeCollectionState

    // call base init
    return s.RowSourceImpl.Init(ctx, configData, opts...)
}

func (s *AccessLogFileSource) GetConfigSchema() parse.Config {
    return &AccessLogFileSourceConfig{}
}

// shouldCollectRow checks if a row should be collected based on our time range logic
func (s *AccessLogFileSource) shouldCollectRow(state []byte, rowTime time.Time) bool {
    // Parse the collection state
    var cs CollectionState
    if err := json.Unmarshal(state, &cs); err != nil {
        slog.Error("Failed to parse collection state", "error", err)
        return false
    }

    // If no ranges, collect everything
    if len(cs.Ranges) == 0 {
        return true
    }

    // Check if the row time falls within any of our ranges
    for _, r := range cs.Ranges {
        // Log the comparison
        slog.Debug("Checking time range",
            "row_time", rowTime.Format(time.RFC3339),
            "start_time", r.StartTime.Format(time.RFC3339),
            "end_time", r.EndTime.Format(time.RFC3339))

        // Time is within range if it's after or equal to start AND before or equal to end
        if !rowTime.Before(r.StartTime) && !rowTime.After(r.EndTime) {
            return true
        }
    }

    return false
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

    // Get initial state
    stateJSON, err := s.GetCollectionStateJSON()
    if err != nil {
        slog.Error("Failed to get initial collection state", "error", err)
    } else {
        slog.Debug("Initial collection state", "state", string(stateJSON))
    }

    scanner := bufio.NewScanner(file)
    linesProcessed := 0
    rowsCollected := 0
    
    for scanner.Scan() {
        line := scanner.Text()
        linesProcessed++

        // Parse the log entry first
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

        // Get current state for time check
        currentState, err := s.GetCollectionStateJSON()
        if err != nil {
            return fmt.Errorf("error getting collection state: %v", err)
        }

        slog.Debug("Processing log entry", 
            "entry_time", logEntry.TimeLocal.Format(time.RFC3339),
            "entry_time_unix", logEntry.TimeLocal.Unix(),
            "uri", logEntry.URI)

        // Check if we should collect this row based on time
        if !s.shouldCollectRow(currentState, logEntry.TimeLocal) {
            slog.Debug("Skipping row due to time range", 
                "time", logEntry.TimeLocal.Format(time.RFC3339),
                "unix_time", logEntry.TimeLocal.Unix(),
                "uri", logEntry.URI)
            continue
        }

        // Create row data with the value
        row := &types.RowData{
            Data:     &logEntry,
            Metadata: sourceEnrichmentFields,
        }

        // Update collection state BEFORE sending the row
        collectionState.Upsert(logEntry.TimeLocal, logEntry.URI, nil)
        
        // Send the row to be processed
        slog.Debug("Sending row for processing",
            "remote_addr", logEntry.RemoteAddr,
            "method", logEntry.Method,
            "uri", logEntry.URI,
            "time", logEntry.TimeLocal.Format(time.RFC3339))

        if err := s.OnRow(ctx, row, currentState); err != nil {
            slog.Error("Error processing row", 
                "error", err,
                "remote_addr", logEntry.RemoteAddr,
                "uri", logEntry.URI)
            return fmt.Errorf("error processing row: %w", err)
        }
        
        rowsCollected++
    }

    slog.Info("File processing complete", 
        "path", filePath,
        "lines_processed", linesProcessed,
        "rows_collected", rowsCollected)

    // Log final state
    finalState, err := s.GetCollectionStateJSON()
    if err != nil {
        slog.Error("Failed to get final collection state", "error", err)
    } else {
        slog.Debug("Final collection state", "state", string(finalState))
    }

    return nil
}

func (s *AccessLogFileSource) Collect(ctx context.Context) error {
    slog.Info("Starting NGINX access log collection")
    
    collectionState := s.CollectionState.(*collection_state.TimeRangeCollectionState[*AccessLogFileSourceConfig])
    collectionState.StartCollection()
    defer collectionState.EndCollection()

    logPath := s.Config.LogPath
    slog.Debug("Using log path", "path", logPath)
    
    // Check if path exists
    _, err := os.Stat(logPath)
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

    // Process single file
    slog.Debug("Processing log file", "path", logPath)
    err = s.processFile(ctx, logPath, location, collectionState)
    if err != nil {
        return fmt.Errorf("error processing file %s: %v", logPath, err)
    }

    return nil
}