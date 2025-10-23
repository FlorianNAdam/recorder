# Recorder
[![Build Docker Image](https://img.shields.io/badge/Build_Docker_Image-passing-brightgreen)](https://github.com/FlorianNAdam/recorder/actions/workflows/build.yml)

A Rust-based recorder for live streams, supporting automatic login, filtering, and recording streams with `ffmpeg`.

## Features

* Automatic login using WebDriver (Selenium / Geckodriver / Chromedriver)
* Supports headless or visible browser
* Converts recordings from MKV to MP4
* Automatic retry on failures
* Whitelist and blacklist stream filtering via regex
* Configurable polling intervals and session timeouts
* Organized recordings and logs per course

## Requirements

* Rust 1.72+
* `ffmpeg` installed and available in PATH
* WebDriver server running (e.g., [Geckodriver](https://github.com/mozilla/geckodriver))

## Installation

```bash
git clone https://github.com/FlorianNAdam
cd recorder
cargo build --release
```

## Usage

```bash
recorder --username <USERNAME> --password <PASSWORD> [OPTIONS]
```

### Options

| Option              | Description                                           | Default                 | Env               |
| ------------------- | ----------------------------------------------------- | ----------------------- | ----------------- |
| `--webdriver-url`   | WebDriver URL                                         | `http://localhost:4444` | `WEBDRIVER_URL`   |
| `--username`        | Login username                                        | —                       | `USERNAME`        |
| `--password`        | Login password                                        | —                       | `PASSWORD`        |
| `--session-timeout` | Duration to use login session                         | `6h`                    | `SESSION_TIMEOUT` |
| `--headless`        | Run browser headless                                  | `true`                  | `HEADLESS`        |
| `--poll-interval`   | Poll interval for new streams                         | `1m`                    | `POLL_INTERVAL`   |
| `--whitelist`       | Comma-separated regex patterns for courses to include | —                       | `WHITELIST`       |
| `--blacklist`       | Comma-separated regex patterns for courses to exclude | —                       | `BLACKLIST`       |
| `--recordings-dir`  | Base directory for recordings                         | `recordings`            | `RECORDINGS_DIR`  |
| `--logs-dir`        | Base directory for logs                               | `logs`                  | `LOGS_DIR`        |


### Example

```bash
recorder \
  --username "myuser" \
  --password "mypassword" \
  --whitelist "Math.*,Physics.*" \
  --blacklist "Archived.*" \
  --poll-interval 30s
```

This will record all live streams from courses starting with "Math" or "Physics", skipping any course that matches "Archived.*".

## Nix Support

### Using Nix Flakes

You can directly run the recorder with:
```bash
nix run github.com:FlorianNAdam/recorder
```

### Using Nix Arion

The following configuration runs the recorder in Docker containers using Nix arion + nirion + sops-nix:

```nix
{
  config,
  host,
  ...
}:
{
  virtualisation.nirion =
    let
      images = {
        "recorder" = "ghcr.io/floriannadam/recorder:latest";
        "webdriver" = "instrumentisto/geckodriver";
      };
    in
    {
      projects.recorder.settings = {
        project.name = "recorder";

        networks.dmz = {
          name = "dmz";
          external = true;
        };
        networks.internal = { };

        services = {
          recorder.service = {
            image = images."recorder";
            container_name = "recorder";
            volumes = [
              "<storage-location>/recorder/logs:/logs"
              "<storage-location>/recorder/recordings:/recordings"
            ];
            env_file = [
              "${config.sops.templates."recorder.env".path}"
            ];
            networks = [
              "dmz"
              "internal"
            ];
            restart = "always";
          };
          recorder-webdriver.service = {
            image = images."webdriver";
            container_name = "recorder-webdriver";
            command = "--host=recorder-webdriver --binary=/opt/firefox/firefox --log=debug";
            networks = [
              "internal"
            ];
            restart = "always";
          };
        };
      };
    };

  sops.secrets."recorder/username" = {
    owner = "${host.username}";
  };
  sops.secrets."recorder/password" = {
    owner = "${host.username}";
  };

  sops.templates."recorder.env" = {
    owner = "${host.username}";
    content = ''
      USERNAME="${config.sops.placeholder."recorder/username"}"
      PASSWORD="${config.sops.placeholder."recorder/password"}"
      WEBDRIVER_URL="http://recorder-webdriver:4444"
      RUST_LOG=info
    '';
  };
}
```

This configuration runs both the recorder and WebDriver in separate containers, with persistent volumes for logs and recordings, and environment variables stored securely via `sops`.

## License

MIT License
