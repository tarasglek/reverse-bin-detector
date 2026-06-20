# Python Detector Behavior Test Matrix

This maps `../reverse-bin-hosting/utils/discover-app/test_discover_app.py` behavior to Go detector test groups. Go test names should stay close to the Python names where practical.

## Detector JSON shape and health override fields

Python source tests:
- `test_build_discovery_result_returns_expected_json_shape`
- `test_build_discovery_result_includes_health_overrides_when_present`
- `test_main_emits_health_overrides_for_opaque_explicit_command_without_entrypoint`
- `test_main_emits_health_overrides_for_autodetected_app`
- `test_main_emits_reverse_bin_health_status`

Go target group:
- Schema/CLI output tests using `detectorschema.Parse`.
- Health method/path/status emission tests in config/build integration tests.

## Env config parsing, partial config, and invalid combinations

Python source tests:
- `test_load_env_app_config_reads_partial_listen_values_without_command`
- `test_load_env_app_config_reads_partial_socket_path_values_without_command`
- `test_load_env_app_config_reads_explicit_listen_values`
- `test_load_env_app_config_reads_health_override_values`
- `test_load_env_app_config_allows_missing_upstream_when_command_is_present`
- `test_load_env_app_config_rejects_listen_and_socket_path_together`
- `test_load_env_app_config_rejects_health_method_without_path`
- `test_load_env_app_config_rejects_health_path_without_method`
- `test_load_env_app_config_reads_health_status`
- `test_load_env_app_config_rejects_health_status_without_method_path`
- `test_load_env_app_config_rejects_health_status_outside_http_range`

Go target group:
- `LoadEnvAppConfig` parser table tests.
- Keep partial config valid when inference can fill command/transport later.
- Keep errors for ambiguous TCP/socket and incomplete health settings.

## `.env` and `secrets.enc.json` source selection

Python source tests:
- `test_find_env_source_rejects_plaintext_and_encrypted_json_files`
- `test_load_app_env_decrypts_sops_json_to_dotenv_without_writing_plaintext`
- `test_main_uses_sops_json_for_app_env`

Go target group:
- Env source loader tests.
- SOPS tests use injected decrypt/runner first, then fake `sops` CLI under Landlock-aware implementation.

## Explicit command handling

Python source tests:
- `test_build_explicit_app_uses_explicit_listen_config`
- `test_build_explicit_app_allocates_port_for_blank_listen`
- `test_build_explicit_app_uses_socket_path_config`
- `test_build_explicit_app_rejects_absolute_socket_path`
- `test_build_explicit_app_rejects_listen_without_parseable_port_suffix`
- `test_main_supplements_missing_upstream_for_explicit_command`
- `test_main_allocates_fallback_for_opaque_explicit_command_without_entrypoint`

Go target group:
- Explicit provider/config tests.
- `REVERSE_BIN_COMMAND` becomes `sh -c <command>`.
- Missing transport for opaque commands uses detector-selected TCP.

## Blank `LISTEN` and `REVERSE_BIN_PORT` free-port allocation

Python source tests:
- `test_build_explicit_app_allocates_port_for_blank_listen`
- `test_resolve_app_replaces_blank_listen_with_resolved_listener`
- `test_resolve_app_allocates_reverse_bin_port_for_blank_port`

Go target group:
- Transport resolver tests.
- Blank TCP values allocate by local bind/listen only; no outgoing dial.

## `SOCKET_PATH` handling and absolute path rejection

Python source tests:
- `test_build_explicit_app_uses_socket_path_config`
- `test_build_explicit_app_rejects_absolute_socket_path`
- `test_resolve_app_preserves_explicit_socket_path_for_python_unix_app`
- `test_resolve_app_unix_socket_does_not_inject_reverse_bin_tcp_envs`
- `test_main_inferrs_main_py_command_from_partial_socket_path_config`
- `test_main_rejects_main_ts_with_explicit_socket_path`

Go target group:
- Transport resolver tests.
- Unix socket paths must be relative and resolved under app dir.
- Deno/static TCP-only providers reject socket transport.

## App entrypoint detection order

Python source tests:
- `test_discover_app_command_ignores_reverse_bin_app_json_during_fallback`
- `test_detect_entrypoint_supports_main_ts_fallback`
- `test_detect_entrypoint_supports_main_py_fallback`
- `test_detect_entrypoint_rejects_main_sh_autodetection`
- `test_main_inferrs_main_py_command_from_partial_listen_config`
- `test_main_inferrs_main_ts_command_from_partial_listen_config`
- `test_resolve_app_detects_root_index_html_after_runtime_entrypoints`
- `test_resolve_app_detects_dist_index_html_after_root_index_html`
- `test_main_rejects_missing_command_and_missing_detectable_entrypoint`

Go target group:
- Local provider detection tests.
- Preserve order: explicit config, `main.ts`, executable `main.py`, `index.html`, `dist/index.html`.
- Keep legacy `reverse-bin-app.json` ignored.

## Child env construction and override behavior

Python source tests:
- `test_build_app_envs_passes_through_dot_env_values`
- `test_build_app_envs_uses_loaded_env_map_without_rereading_dot_env_file`
- `test_build_app_envs_applies_overrides`
- `test_resolve_app_preserves_explicit_listen_in_child_envs`
- `test_resolve_app_never_injects_reverse_proxy_to_into_child_envs`
- `test_resolve_app_infers_tcp_listener_for_main_py_child_envs`
- `test_resolve_app_uses_fixed_reverse_bin_port`
- `test_resolve_app_uses_reverse_bin_host`
- `test_main_emits_autodetected_listen_for_main_py_without_env`

Go target group:
- Env builder tests.
- Preserve input `.env` entries unless resolved transport overrides blank/missing runtime bind values.
- Never emit legacy `REVERSE_PROXY_TO`.

## Deno app behavior and Smallweb-compatible permissive flags

Python source tests:
- `test_resolve_app_sets_deno_no_update_check_for_main_ts`
- `test_discover_app_command_ignores_reverse_bin_app_json_during_fallback`
- `test_detect_entrypoint_supports_main_ts_fallback`
- `test_main_inferrs_main_ts_command_from_partial_listen_config`
- `test_main_rejects_main_ts_with_explicit_socket_path`

Go target group:
- Deno provider/build tests.
- Preserve command shape: `deno serve --watch --allow-all --host <host> --port <port> main.ts`.
- Preserve `DENO_NO_UPDATE_CHECK=1`.

## CLI success/error behavior

Python source tests:
- `test_main_emits_explicit_listen_config_without_sandbox`
- `test_main_rejects_missing_command_and_missing_detectable_entrypoint`
- `test_main_rejects_partial_health_override`
- `test_main_uses_sops_json_for_app_env`
- `test_main_emits_reverse_bin_health_status`

Go target group:
- End-to-end CLI tests.
- Success emits strict detector JSON.
- Errors exit non-zero and write useful diagnostics to stderr.

## Sandbox behavior split

Python source tests:
- `test_wrap_landrun_keeps_default_filesystem_policy_narrow`

Go target group:
- Runtime sandbox command/policy tests.
- Detection Landlock tests are new Go-only coverage and intentionally stricter: read-only filesystem, TCP bind allowed, outgoing TCP connect denied.

## Intentional behavior differences

Document differences in the Go tests that assert them:
- Python autodetected `main.py` historically allocated TCP when no transport was provided. This Go port defaults Python apps to `SOCKET_PATH=data/reverse-bin.sock` per the current migration plan.
- Detection itself runs under Landlock in Go; Python only tested runtime `landrun` command shape.
