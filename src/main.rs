use chrono::{DateTime, TimeZone, Utc};
use clap::Parser;
use regex::Regex;
use reqwest::cookie::Jar;
use reqwest::Client;
use serde::Deserialize;
use tokio::fs::remove_file;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::{fs::File, sync::Mutex};

use sanitize_filename::sanitize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use thirtyfour::prelude::*;
use tokio::time::{sleep, Instant};
use url::Url;

use log::{error, info};

pub fn convert_thirtyfour_cookies(
    cookies: &[thirtyfour::Cookie],
    current_url: &str,
) -> Vec<(String, Url)> {
    let current_url_parsed =
        Url::parse(current_url).expect("Invalid current URL");
    let mut result = Vec::new();
    for c in cookies {
        let mut cookie_str = format!("{}={}", c.name, c.value);
        let domain = c.domain.clone().or_else(|| {
            current_url_parsed
                .domain()
                .map(|d| d.to_string())
        });
        let path = c
            .path
            .clone()
            .unwrap_or_else(|| "/".into());
        if let Some(ref d) = domain {
            cookie_str.push_str(&format!("; Domain={}", d));
        }
        cookie_str.push_str(&format!("; Path={}", path));
        if c.secure.unwrap_or(false) {
            cookie_str.push_str("; Secure");
        }
        if let Some(expiry_ts) = c.expiry {
            let expiry_dt = Utc.timestamp_opt(expiry_ts, 0).single();
            if let Some(dt) = expiry_dt {
                cookie_str.push_str(&format!("; Expires={}", dt.to_rfc2822()));
            }
        }
        if let Some(same_site) = &c.same_site {
            cookie_str.push_str(&format!("; SameSite={:?}", same_site));
        }
        let scheme = if c.secure.unwrap_or(false) {
            "https"
        } else {
            "http"
        };
        let url_for_cookie = if let Some(ref d) = domain {
            Url::parse(&format!("{}://{}", scheme, d))
                .unwrap_or_else(|_| current_url_parsed.clone())
        } else {
            current_url_parsed.clone()
        };
        result.push((cookie_str, url_for_cookie));
    }
    result
}

async fn run_recorder(
    stream: &Stream,
    _cookies: &String,
) -> anyhow::Result<()> {
    info!(
        "Running recorder for stream {}: {} - {}",
        stream.id, stream.course, stream.name
    );

    let safe_course = sanitize(&stream.course);
    let safe_name = sanitize(&stream.name);

    let base_dir = Path::new("recordings").join(&safe_course);
    let log_dir = Path::new("logs").join(&safe_course);

    tokio::fs::create_dir_all(&base_dir).await?;
    tokio::fs::create_dir_all(&log_dir).await?;

    let out_file = base_dir.join(format!("{}.mkv", safe_name));
    let final_file = base_dir.join(format!("{}.mp4", safe_name));

    let stderr_log = log_dir.join(format!("{}.log", safe_name));
    let stderr_file = File::create(&stderr_log).await?;

    let mut url = stream.url.clone();
    url.set_query(Some("dvr"));

    let mut command = Command::new("ffmpeg");
    command.args(&[
        "-i",
        url.as_str(),
        "-c",
        "copy",
        "-y",
        out_file.to_str().unwrap(),
    ]);

    info!(
        "Running ffmpeg: \"ffmpeg {}\"",
        command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );

    let mut child = command
        .stderr(Stdio::from(stderr_file.into_std().await))
        .spawn()?;

    let status = child.wait().await?;
    if !status.success() {
        anyhow::bail!("ffmpeg failed (exit code: {})", status)
    }

    let stderr_log = log_dir.join(format!("{}_convert.log", safe_name));
    let stderr_file = File::create(&stderr_log).await?;

    info!("Converting to mp4: {:?}", out_file);

    let mut command = Command::new("ffmpeg");
    command.args(&[
        "-i",
        out_file.to_str().unwrap(),
        "-codec",
        "copy",
        "-y",
        final_file.to_str().unwrap(),
    ]);

    info!(
        "Running ffmpeg: \"ffmpeg {}\"",
        command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );

    let mut child = command
        .stderr(Stdio::from(stderr_file.into_std().await))
        .spawn()?;

    let status = child.wait().await?;
    if !status.success() {
        anyhow::bail!("ffmpeg failed (exit code: {})", status)
    }

    info!("Deleting mkv: {:?}", out_file);

    remove_file(out_file).await?;

    Ok(())
}

#[allow(dead_code)]
struct Recorder {
    stream: Stream,
    status: RecorderStatus,
    handle: JoinHandle<()>,
}

enum RecorderStatus {
    Recording,
    Finished,
    Failed,
}

async fn create_recorder(
    stream: Stream,
    cookies: String,
    recorders: Arc<Mutex<HashMap<i64, Recorder>>>,
) {
    let id = stream.id;
    let mut locked_recorders = recorders.lock().await;
    if !locked_recorders.contains_key(&id) {
        let handle = {
            let recorders = recorders.clone();
            let stream = stream.clone();
            let cookies = cookies.clone();

            tokio::spawn(async move {
                let mut delay = Duration::from_secs(2);

                loop {
                    match run_recorder(&stream, &cookies).await {
                        Ok(()) => {
                            info!(
                                "Finished recording: {} - {}",
                                stream.course, stream.name
                            );
                            let mut locked_recorders = recorders.lock().await;
                            if let Some(recorder) =
                                locked_recorders.get_mut(&id)
                            {
                                recorder.status = RecorderStatus::Finished;
                            }
                            break;
                        }
                        Err(e) => {
                            error!(
                                "Failed recording: {} - {} due to: {:#?}. Retrying in {:?}...",
                                stream.course, stream.name, e, delay
                            );
                            {
                                let mut locked_recorders =
                                    recorders.lock().await;
                                if let Some(recorder) =
                                    locked_recorders.get_mut(&id)
                                {
                                    recorder.status = RecorderStatus::Failed;
                                }
                            }
                            sleep(delay).await;
                            delay *= 2;
                        }
                    }
                }
            })
        };

        let recorder = Recorder {
            stream,
            status: RecorderStatus::Recording,
            handle,
        };

        locked_recorders.insert(id, recorder);
    }
}

async fn inner_login(
    driver: &WebDriver,
    username: &str,
    password: &str,
) -> anyhow::Result<Vec<(String, Url)>> {
    driver
        .goto("https://live.rbg.tum.de/saml/out")
        .await?;

    let username_input = driver
        .query(By::Id("username"))
        .wait(Duration::from_secs(10), Duration::from_millis(500))
        .first()
        .await?;
    username_input
        .send_keys(username)
        .await?;

    let password_input = driver
        .query(By::Id("password"))
        .wait(Duration::from_secs(10), Duration::from_millis(500))
        .first()
        .await?;
    password_input
        .send_keys(password)
        .await?;

    let submit_button = driver.find(By::Id("btnLogin")).await?;
    submit_button.click().await?;

    sleep(Duration::from_secs(1)).await;

    let cookies = driver.get_all_cookies().await?;
    let current_url = driver.current_url().await?;

    let cookie_pairs =
        convert_thirtyfour_cookies(&cookies, &current_url.to_string());

    Ok(cookie_pairs)
}

async fn login(
    webdriver_url: &str,
    username: &str,
    password: &str,
    headless: bool,
) -> anyhow::Result<Vec<(String, Url)>> {
    let mut caps = DesiredCapabilities::firefox();
    if headless {
        caps.set_headless()?;
    }
    let driver = WebDriver::new(webdriver_url, caps).await?;
    let result = inner_login(&driver, username, password).await;
    let source = driver.source().await;
    driver.quit().await?;

    match result {
        Ok(cookies) => Ok(cookies),
        Err(e) => {
            error!("Page: {:#?}", source);
            return Err(e);
        }
    }
}

async fn login_with_backoff(
    webdriver_url: &str,
    username: &str,
    password: &str,
    headless: bool,
) -> Vec<(String, Url)> {
    let mut attempt = 0;
    let mut delay = Duration::from_secs(1);

    loop {
        attempt += 1;
        info!("Attempting login");
        match login(webdriver_url, username, password, headless).await {
            Ok(cookies) => return cookies,
            Err(e) => {
                error!(
                    "Login attempt {} failed: {:#?}. Retrying in {:?}...",
                    attempt, e, delay
                );
                sleep(delay).await;
                delay *= 2;
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Stream {
    id: i64,
    course: String,
    name: String,
    url: Url,
}

fn extract_stream(live_course: StreamInfo) -> Option<Stream> {
    let course_name = live_course.course?.name?;
    let stream = live_course.stream?;
    let stream_id = stream.id? as i64;

    let name = {
        let date_prefix = stream.start.as_ref().and_then(|s| {
            s.parse::<DateTime<Utc>>()
                .ok()
                .map(|dt| dt.format("%Y-%m-%d_%H:%M").to_string())
        });

        let base_name = stream
            .name
            .clone()
            .filter(|n| !n.is_empty());

        match (date_prefix, base_name) {
            (Some(date), Some(name)) => format!("{}_{}", date, name),
            (Some(date), None) => date,
            (None, Some(name)) => name,
            (None, None) => stream_id.to_string(),
        }
    };

    let url = stream.hls_url?;
    let url = Url::from_str(&url).ok()?;

    Some(Stream {
        id: stream_id,
        course: course_name,
        name,
        url,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StreamInfo {
    pub course: Option<Course>,
    pub stream: Option<StreamV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Course {
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StreamV1 {
    #[serde(rename = "ID")]
    pub id: Option<u32>,
    pub name: Option<String>,
    #[serde(rename = "HLSUrl")]
    pub hls_url: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub duration: Option<u32>,
}

async fn get_streams(client: Client) -> anyhow::Result<Vec<Stream>> {
    info!("Getting streams");

    let response = client
        .get("https://live.rbg.tum.de/api/courses/live")
        .send()
        .await?
        .error_for_status()?;

    let live_courses: Vec<StreamInfo> = response.json().await?;

    let mut streams = Vec::new();
    for live_course in live_courses {
        if let Some(stream) = extract_stream(live_course) {
            streams.push(stream);
        }
    }
    Ok(streams)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// WebDriver URL (default: http://localhost:4444)
    #[arg(
        long,
        env = "WEBDRIVER_URL",
        default_value = "http://localhost:4444"
    )]
    webdriver_url: String,

    /// username
    #[arg(long, env = "USERNAME")]
    username: String,

    /// password
    #[arg(long, env = "PASSWORD")]
    password: String,

    /// How long to use a login session
    #[arg(long, env = "SESSION_TIMEOUT", value_parser = humantime::parse_duration, default_value = "6h")]
    session_timeout: Duration,

    /// Run browser in headless mode
    #[arg(long, env = "HEADLESS", default_value_t = true)]
    headless: bool,

    /// Poll interval for checking new streams
    #[arg(long, env = "POLL_INTERVAL", value_parser = humantime::parse_duration, default_value = "1m")]
    poll_interval: Duration,

    /// Whitelist regex patterns for course names
    #[arg(long, env = "WHITELIST", value_delimiter = ',', value_parser=Regex::new)]
    whitelist: Vec<Regex>,

    /// Blacklist regex patterns for course names
    #[arg(long, env = "BLACKLIST", value_delimiter = ',', value_parser=Regex::new)]
    blacklist: Vec<Regex>,

    /// Recordings base directory
    #[arg(long, env = "RECORDINGS_DIR", default_value = "recordings")]
    recordings_dir: String,

    /// Logs base directory
    #[arg(long, env = "LOGS_DIR", default_value = "logs")]
    logs_dir: String,
}

async fn create_client(cookies: &[(String, Url)]) -> Client {
    let jar = Jar::default();
    for (cookie_str, url) in cookies {
        info!("Cookie {}: {}", url, cookie_str);
        jar.add_cookie_str(&cookie_str, &url);
    }

    reqwest::Client::builder()
        .cookie_provider(Arc::new(jar))
        .build()
        .expect("failed creating reqwest client")
}

fn should_record_stream(stream: &Stream, args: &Args) -> bool {
    let course_name = &stream.course;

    // Check blacklist first
    for pattern in &args.blacklist {
        if pattern.is_match(course_name) {
            info!(
                "Skipping stream '{}' due to blacklist pattern: {}",
                course_name, pattern
            );
            return false;
        }
    }

    // Check whitelist
    if !args.whitelist.is_empty() {
        for pattern in &args.whitelist {
            if pattern.is_match(course_name) {
                info!(
                    "Including stream '{}' due to whitelist pattern: {}",
                    course_name, pattern
                );
                return true;
            }
        }
        // If whitelist exists but no patterns match, exclude
        info!(
            "Skipping stream '{}' - no whitelist pattern matches",
            course_name
        );
        return false;
    }

    // If no whitelist, include all (unless blacklisted)
    true
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    info!("Starting RBG recorder...");

    let args = Args::parse();

    let recorders: Arc<Mutex<HashMap<i64, Recorder>>> = Default::default();

    let mut cookies = login_with_backoff(
        &args.webdriver_url,
        &args.username,
        &args.password,
        args.headless,
    )
    .await;
    let mut client = create_client(&cookies).await;
    let mut last_login = Instant::now();

    loop {
        if last_login.elapsed() >= args.session_timeout {
            cookies = login_with_backoff(
                &args.webdriver_url,
                &args.username,
                &args.password,
                args.headless,
            )
            .await;
            client = create_client(&cookies).await;
            last_login = Instant::now();
        }

        let client = client.clone();
        match get_streams(client).await {
            Ok(streams) => {
                for stream in streams {
                    let recorders = recorders.clone();

                    let cookies = cookies
                        .iter()
                        .map(|(cookie, _)| cookie.as_str())
                        .collect::<Vec<&str>>()
                        .join("; ");

                    if should_record_stream(&stream, &args) {
                        create_recorder(stream, cookies, recorders).await
                    }
                }
            }
            Err(e) => error!("Failed getting courses: {:#?}", e),
        }

        sleep(args.poll_interval).await;
    }
}
