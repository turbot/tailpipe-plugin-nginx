## v0.3.1 [2025-07-28]

_Dependencies_

- Recompiled plugin with [tailpipe-plugin-sdk v0.9.2](https://github.com/turbot/tailpipe-plugin-sdk/blob/develop/CHANGELOG.md#v092-2025-07-24) that fixes incorrect data ranges for zero‑granularity collections and prevents crashes in certain collection states. ([#45](https://github.com/turbot/tailpipe-plugin-nginx/pull/45))

## v0.3.0 [2025-07-02]

_Dependencies_

- Recompiled plugin with [tailpipe-plugin-sdk v0.9.1](https://github.com/turbot/tailpipe-plugin-sdk/blob/develop/CHANGELOG.md#v091-2025-07-02) to support the `--to` flag, directional time-based collection, improved tracking of collected data and fixed collection state issues. ([#43](https://github.com/turbot/tailpipe-plugin-nginx/pull/43))

## v0.2.1 [2025-06-04]

- Recompiled plugin with [tailpipe-plugin-sdk v0.7.1](https://github.com/turbot/tailpipe-plugin-sdk/blob/develop/CHANGELOG.md#v071-2025-06-04) that fixes an issue affecting collections using a file source. ([#38](https://github.com/turbot/tailpipe-plugin-nginx/pull/38))

## v0.2.0 [2025-06-03]

_Dependencies_

- Recompiled plugin with [tailpipe-plugin-sdk v0.7.0](https://github.com/turbot/tailpipe-plugin-sdk/blob/develop/CHANGELOG.md#v070-2025-06-03) that improves how collection end times are tracked, helping make future collections more accurate and reliable. ([#37](https://github.com/turbot/tailpipe-plugin-nginx/pull/37))

## v0.1.1 [2025-04-03]

_Bug fixes_

- Renamed `nginx_access_log` default format from `default` to `combined`.

## v0.1.0 [2025-04-02]

_What's new?_

- New tables added
  - [nginx_access_log](https://hub.tailpipe.io/plugins/turbot/nginx/tables/nginx_access_log)
