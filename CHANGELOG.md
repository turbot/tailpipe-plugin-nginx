## v0.1.1 [2025-04-03]

_Bug fixes_

- Renamed `nginx_access_log` default format from `default` to `combined`.

## v0.1.0 [2025-04-02]

_What's new?_

- New tables added
  - [nginx_access_log](https://hub.tailpipe.io/plugins/turbot/nginx/tables/nginx_access_log)
    - Query Nginx access logs with combined log format
    - Support for file-based collection, compressed logs (gzip, zip), and AWS S3 integration
    - Built-in queries for analyzing failed requests, large responses, and traffic patterns
