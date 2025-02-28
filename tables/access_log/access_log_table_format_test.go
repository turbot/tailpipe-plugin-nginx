package access_log

import (
	"regexp"
	"testing"
)

func Test_AccessLogTableFormat_GetRegex(t *testing.T) {
	type args struct {
		layout  string
		logLine string
	}

	tests := []struct {
		name    string
		args    args
		want    string // regex
		wantOut map[string]string
		wantErr bool
	}{
		{
			name: "Default nginx format",
			args: args{
				layout:  `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`,
				logLine: `127.0.0.1 - turbie [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "https://example.com" "Mozilla/5.0"`,
			},
			want:    `^(?P<remote_addr>[^ ]*) - (?P<remote_user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?" (?P<status>[^ ]*) (?P<body_bytes_sent>[^ ]*) "(?P<http_referer>.*?)" "(?P<http_user_agent>.*?)"`,
			wantErr: false,
			wantOut: map[string]string{
				"remote_addr":     "127.0.0.1",
				"remote_user":     "turbie",
				"time_local":      "10/Oct/2024:13:55:36 -0700",
				"request_method":  "GET",
				"request_uri":     "/index.html",
				"server_protocol": "HTTP/1.1",
				"status":          "200",
				"body_bytes_sent": "2326",
				"http_referer":    "https://example.com",
				"http_user_agent": "Mozilla/5.0",
			},
		},
		{
			name: "Default nginx format - host alternative",
			args: args{
				layout:  `$remote_addr $host $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`,
				logLine: `127.0.0.1 example.com turbie [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "https://example.com" "Mozilla/5.0"`,
			},
			want:    `^(?P<remote_addr>[^ ]*) (?P<host>[^ ]*) (?P<remote_user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?" (?P<status>[^ ]*) (?P<body_bytes_sent>[^ ]*) "(?P<http_referer>.*?)" "(?P<http_user_agent>.*?)"`,
			wantErr: false,
			wantOut: map[string]string{
				"remote_addr":     "127.0.0.1",
				"host":            "example.com",
				"remote_user":     "turbie",
				"time_local":      "10/Oct/2024:13:55:36 -0700",
				"request_method":  "GET",
				"request_uri":     "/index.html",
				"server_protocol": "HTTP/1.1",
				"status":          "200",
				"body_bytes_sent": "2326",
				"http_referer":    "https://example.com",
				"http_user_agent": "Mozilla/5.0",
			},
		},
		{
			name: "Custom format with upstream times",
			args: args{
				layout:  `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent $upstream_response_time $upstream_connect_time`,
				logLine: `192.168.1.2 - admin [10/Oct/2024:13:55:36 -0700] "POST /api HTTP/1.1" 201 512 0.123 0.004`,
			},
			want:    `^(?P<remote_addr>[^ ]*) - (?P<remote_user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?" (?P<status>[^ ]*) (?P<body_bytes_sent>[^ ]*) (?P<upstream_response_time>[^ ]*) (?P<upstream_connect_time>[^ ]*)`,
			wantErr: false,
			wantOut: map[string]string{
				"remote_addr":            "192.168.1.2",
				"remote_user":            "admin",
				"time_local":             "10/Oct/2024:13:55:36 -0700",
				"request_method":         "POST",
				"request_uri":            "/api",
				"server_protocol":        "HTTP/1.1",
				"status":                 "201",
				"body_bytes_sent":        "512",
				"upstream_response_time": "0.123",
				"upstream_connect_time":  "0.004",
			},
		},
		{
			name: "Custom format with ssl fields",
			args: args{
				layout:  `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent $ssl_protocol $ssl_cipher`,
				logLine: `203.0.113.1 - - [10/Oct/2024:13:55:36 -0700] "GET /secure HTTP/1.1" 200 2326 TLSv1.3 AES256-GCM-SHA384`,
			},
			want:    `^(?P<remote_addr>[^ ]*) - (?P<remote_user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?" (?P<status>[^ ]*) (?P<body_bytes_sent>[^ ]*) (?P<ssl_protocol>[^ ]*) (?P<ssl_cipher>[^ ]*)`,
			wantErr: false,
			wantOut: map[string]string{
				"remote_addr":     "203.0.113.1",
				"remote_user":     "-",
				"time_local":      "10/Oct/2024:13:55:36 -0700",
				"request_method":  "GET",
				"request_uri":     "/secure",
				"server_protocol": "HTTP/1.1",
				"status":          "200",
				"body_bytes_sent": "2326",
				"ssl_protocol":    "TLSv1.3",
				"ssl_cipher":      "AES256-GCM-SHA384",
			},
		},
		{
			name: "Custom format with shuffled fields",
			args: args{
				layout:  `$scheme $remote_addr $remote_user [$time_local] "$request" $status $body_bytes_sent $http_host`,
				logLine: `https 192.168.1.1 user123 [10/Oct/2024:13:55:36 -0700] "POST /api/data HTTP/2" 201 1024 example.com`,
			},
			want:    `^(?P<scheme>[^ ]*) (?P<remote_addr>[^ ]*) (?P<remote_user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?" (?P<status>[^ ]*) (?P<body_bytes_sent>[^ ]*) (?P<http_host>[^ ]*)`,
			wantErr: false,
			wantOut: map[string]string{
				"scheme":          "https",
				"remote_addr":     "192.168.1.1",
				"remote_user":     "user123",
				"time_local":      "10/Oct/2024:13:55:36 -0700",
				"request_method":  "POST",
				"request_uri":     "/api/data",
				"server_protocol": "HTTP/2",
				"status":          "201",
				"body_bytes_sent": "1024",
				"http_host":       "example.com",
			},
		},
		{
			name: "Custom format with many shuffled fields",
			args: args{
				layout:  `$scheme $http_host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent $request_length $bytes_sent $upstream_addr $upstream_status $upstream_response_time $upstream_connect_time $upstream_header_time $gzip_ratio`,
				logLine: `https example.com 192.168.1.5 - admin [10/Oct/2024:13:55:36 -0700] "GET /dashboard HTTP/2" 200 5643 1024 4500 192.168.1.10:80 200 0.123 0.002 0.056 2.5`,
			},
			want:    `^(?P<scheme>[^ ]*) (?P<http_host>[^ ]*) (?P<remote_addr>[^ ]*) - (?P<remote_user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?" (?P<status>[^ ]*) (?P<body_bytes_sent>[^ ]*) (?P<request_length>[^ ]*) (?P<bytes_sent>[^ ]*) (?P<upstream_addr>[^ ]*) (?P<upstream_status>[^ ]*) (?P<upstream_response_time>[^ ]*) (?P<upstream_connect_time>[^ ]*) (?P<upstream_header_time>[^ ]*) (?P<gzip_ratio>[^ ]*)`,
			wantErr: false,
			wantOut: map[string]string{
				"scheme":                 "https",
				"http_host":              "example.com",
				"remote_addr":            "192.168.1.5",
				"remote_user":            "admin",
				"time_local":             "10/Oct/2024:13:55:36 -0700",
				"request_method":         "GET",
				"request_uri":            "/dashboard",
				"server_protocol":        "HTTP/2",
				"status":                 "200",
				"body_bytes_sent":        "5643",
				"request_length":         "1024",
				"bytes_sent":             "4500",
				"upstream_addr":          "192.168.1.10:80",
				"upstream_status":        "200",
				"upstream_response_time": "0.123",
				"upstream_connect_time":  "0.002",
				"upstream_header_time":   "0.056",
				"gzip_ratio":             "2.5",
			},
		},
		{
			name: "Custom format using time_iso8601 at start",
			args: args{
				layout:  `$time_iso8601 $remote_addr - $remote_user "$request" $status $body_bytes_sent`,
				logLine: `2024-10-10T13:55:36+00:00 127.0.0.1 - user "POST /submit HTTP/1.1" 201 4321`,
			},
			want:    `^(?P<time_iso8601>[^ ]*) (?P<remote_addr>[^ ]*) - (?P<remote_user>[^ ]*) "(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?" (?P<status>[^ ]*) (?P<body_bytes_sent>[^ ]*)`,
			wantErr: false,
			wantOut: map[string]string{
				"time_iso8601":    "2024-10-10T13:55:36+00:00",
				"remote_addr":     "127.0.0.1",
				"remote_user":     "user",
				"request_method":  "POST",
				"request_uri":     "/submit",
				"server_protocol": "HTTP/1.1",
				"status":          "201",
				"body_bytes_sent": "4321",
			},
		},
		{
			name: "Custom format with typo in token",
			args: args{
				layout:  `$remote_addr - $remote_usr [$time_local] "$request" $status $body_bytes_sent`,
				logLine: `127.0.0.1 - turbie [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326`,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Time_Local Expected to be in format [$time_local] what if we don't wrap token in [], noting it has spaces?",
			args: args{
				layout:  `$remote_addr - $remote_user $time_local "$request" $status $body_bytes_sent`,
				logLine: `127.0.0.1 - turbie 10/Oct/2024:13:55:36 -0700 "GET /index.html HTTP/1.1" 200 2326`,
			},
			want:    `^(?P<remote_addr>[^ ]*) - (?P<remote_user>[^ ]*) (?P<time_local>[^\]]*) "(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?" (?P<status>[^ ]*) (?P<body_bytes_sent>[^ ]*)`,
			wantErr: false,
			wantOut: map[string]string{
				"remote_addr":     "127.0.0.1",
				"remote_user":     "turbie",
				"time_local":      "10/Oct/2024:13:55:36 -0700",
				"request_method":  "GET",
				"request_uri":     "/index.html",
				"server_protocol": "HTTP/1.1",
				"status":          "200",
				"body_bytes_sent": "2326",
			},
		},
		{
			name: "Two tokens together",
			args: args{
				layout:  `$remote_addr$status`,
				logLine: `127.0.0.1200`,
			},
			want:    `^(?P<remote_addr>[^ ]*)(?P<status>[^ ]*)`,
			wantErr: true,
			wantOut: map[string]string{
				"remote_addr": "127.0.0.1",
				"status":      "200",
			},
		},
		{
			name: "Request has an escaped quote",
			args: args{
				layout:  `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent`,
				logLine: `127.0.0.1 - - [10/Oct/2024:13:55:36 -0700] "GET /index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5(\"hi\"));?>+/tmp/index1.php HTTP/1.1" 200 2326`,
			},
			want:    `^(?P<remote_addr>[^ ]*) - (?P<remote_user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<request_method>\S+)(?: +(?P<request_uri>[^ ]+))?(?: +(?P<server_protocol>\S+))?" (?P<status>[^ ]*) (?P<body_bytes_sent>[^ ]*)`,
			wantErr: false,
			wantOut: map[string]string{
				"remote_addr":     "127.0.0.1",
				"remote_user":     "-",
				"time_local":      "10/Oct/2024:13:55:36 -0700",
				"request_method":  "GET",
				"request_uri":     `/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5(\"hi\"));?>+/tmp/index1.php`,
				"server_protocol": "HTTP/1.1",
				"status":          "200",
				"body_bytes_sent": "2326",
			},
		},
		{
			name: "Quoted remote_addr",
			args: args{
				layout:  `"$remote_addr"`,
				logLine: `"123.456.123.456"`,
			},
			want:    `^"(?P<remote_addr>[^ ]*)"`,
			wantErr: false,
			wantOut: map[string]string{
				"remote_addr": "123.456.123.456",
			},
		},
		{
			name: "Bracketed remote_addr",
			args: args{
				layout:  `($remote_addr)`,
				logLine: `(123.456.123.456)`,
			},
			want:    `^\((?P<remote_addr>[^ ]*)\)`,
			wantErr: false,
			wantOut: map[string]string{
				"remote_addr": "123.456.123.456",
			},
		},
	}

	for _, tt := range tests {
		format := &AccessLogTableFormat{
			Layout: tt.args.layout,
			Name:   "test",
		}
		t.Run(tt.name, func(t *testing.T) {
			got, err := format.getRegex()
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("unexpected error: %v", err)
			}

			// validate regex matches expected regex
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}

			// validate regex compiles
			re, err := regexp.Compile(got)
			if err != nil {
				t.Fatalf("error regex compile failed: %v", err)
			}

			// validate regex matches given log line
			if !re.MatchString(tt.args.logLine) {
				t.Errorf("regex %v does not match %v", got, tt.args.logLine)
			}

			// validate matches
			match := re.FindStringSubmatch(tt.args.logLine)
			groupNames := re.SubexpNames()
			matches := make(map[string]string)
			for i, name := range groupNames {
				if i > 0 && name != "" {
					matches[name] = match[i]
				}
			}
			for wantKey, wantValue := range tt.wantOut {
				if gotValue, ok := matches[wantKey]; ok {
					if gotValue != wantValue {
						t.Errorf("got %s, want %s", gotValue, wantValue)
					}
				} else {
					t.Errorf("key %s not found in matches", wantKey)
				}
			}

		})
	}
}
