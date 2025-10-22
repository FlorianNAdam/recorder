use chrono::{DateTime, TimeZone, Utc};
use clap::Parser;
use rbg_client::apis::configuration::Configuration;
use rbg_client::models::ProtobufCourseStream;
use reqwest::cookie::Jar;
use reqwest::Client;
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

use rbg_client;

use log::{error, info, warn};

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
    let out_file = base_dir.join(format!("{}.mkv", safe_name));
    let final_file = base_dir.join(format!("{}.mp4", safe_name));
    let log_dir = base_dir.join("logs");

    tokio::fs::create_dir_all(&log_dir).await?;

    let stdout_log = log_dir.join(format!("{}_stdout.log", safe_name));
    let stderr_log = log_dir.join(format!("{}_stderr.log", safe_name));

    let stdout_file = File::create(&stdout_log).await?;
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

    info!("running ffmpeg: {:?}", command.as_std());

    let mut child = command
        .stdout(Stdio::from(stdout_file.into_std().await))
        .stderr(Stdio::from(stderr_file.into_std().await))
        .spawn()?;

    let status = child.wait().await?;
    if !status.success() {
        anyhow::bail!("ffmpeg failed (exit code: {})", status)
    }

    let stdout_log = log_dir.join(format!("{}_convert_stdout.log", safe_name));
    let stderr_log = log_dir.join(format!("{}_convert_stderr.log", safe_name));

    let stdout_file = File::create(&stdout_log).await?;
    let stderr_file = File::create(&stderr_log).await?;

    info!("converting to mp4: {}", safe_name);

    let mut child = Command::new("ffmpeg")
        .args(&[
            "-i",
            out_file.to_str().unwrap(),
            "-codec",
            "copy",
            "-y",
            final_file.to_str().unwrap(),
        ])
        .stdout(Stdio::from(stdout_file.into_std().await))
        .stderr(Stdio::from(stderr_file.into_std().await))
        .spawn()?;

    let status = child.wait().await?;
    info!("ffmpeg exited with: {}", status);

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

fn extract_stream_v1(live_course: StreamInfo) -> Option<Stream> {
    let course_name = live_course.course?.name?;
    let stream = live_course.stream?;
    let stream_id = stream.id? as i64;

    let name = stream
        .name
        .filter(|name| !name.is_empty())
        .clone()
        .or_else(|| {
            stream.start.as_ref().and_then(|s| {
                s.parse::<DateTime<Utc>>()
                    .ok()
                    .map(|dt| dt.format("%Y-%m-%d_%H:%M").to_string())
            })
        })
        .unwrap_or_else(|| stream_id.to_string());

    let url = stream.hls_url?;
    let url = Url::from_str(&url).ok()?;

    Some(Stream {
        id: stream_id,
        course: course_name,
        name,
        url,
    })
}

fn extract_stream_v2(live_course: ProtobufCourseStream) -> Option<Stream> {
    let course_name = live_course.course?.name?;
    let stream = live_course.stream?;
    let stream_id = stream.id?;

    let name = stream
        .name
        .filter(|name| !name.is_empty())
        .clone()
        .or_else(|| {
            stream.start.as_ref().and_then(|s| {
                s.parse::<DateTime<Utc>>()
                    .ok()
                    .map(|dt| dt.format("%Y-%m-%d_%H:%M").to_string())
            })
        })
        .unwrap_or_else(|| stream_id.to_string());

    let url = stream
        .hls_url
        .filter(|s| !s.is_empty())
        .or(stream.playlist_url)
        .filter(|s| !s.is_empty())
        .or(stream.playlist_url_pres)
        .filter(|s| !s.is_empty())
        .or(stream.playlist_url_cam)?;

    let url = Url::from_str(&url).ok()?;

    Some(Stream {
        id: stream_id,
        course: course_name,
        name,
        url,
    })
}

async fn get_streams(client: Client) -> anyhow::Result<Vec<Stream>> {
    match get_streams_v2(client.clone()).await {
        Ok(streams) => Ok(streams),
        Err(e) => {
            warn!("failed getting courses with v2 api: {:#?}", e);
            get_streams_v1(client).await
        }
    }
}

use serde::Deserialize;

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

async fn get_streams_v1(client: Client) -> anyhow::Result<Vec<Stream>> {
    info!("Getting streams with api v1");

    let response = client
        .get("https://live.rbg.tum.de/api/courses/live")
        .send()
        .await?
        .error_for_status()?;

    let live_courses: Vec<StreamInfo> = response.json().await?;

    let mut streams = Vec::new();
    for live_course in live_courses {
        if let Some(stream) = extract_stream_v1(live_course) {
            streams.push(stream);
        }
    }
    Ok(streams)
}

async fn get_streams_v2(client: Client) -> anyhow::Result<Vec<Stream>> {
    info!("Getting streams with api v2");

    let mut configuration = Configuration::new();
    configuration.client = client.clone();

    let live_courses =
        rbg_client::apis::courses_api::get_live_courses(&configuration).await?;

    let mut streams = Vec::new();
    if let Some(live_courses) = live_courses.live_courses {
        for live_course in live_courses {
            if let Some(stream) = extract_stream_v2(live_course) {
                streams.push(stream);
            }
        }
    }
    Ok(streams)
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum ApiMode {
    V1,
    V2,
    Both,
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

    /// TUM username
    #[arg(long, env = "TUM_USERNAME")]
    username: String,

    /// TUM password
    #[arg(long, env = "TUM_PASSWORD")]
    password: String,

    /// How long to use a login session
    #[arg(long, default_value_t = 10)]
    session_timeout: u64,

    /// Run browser in headless mode
    #[arg(long, default_value_t = true)]
    headless: bool,

    /// Poll interval in seconds for checking new streams
    #[arg(long, default_value_t = 10)]
    poll_interval: u64,

    /// API mode: v1, v2, or both (default: both)
    #[arg(long, value_enum, default_value_t = ApiMode::V1)]
    mode: ApiMode,
}

async fn create_client(cookies: &[(String, Url)]) -> Client {
    let jar = Jar::default();
    for (cookie_str, url) in cookies {
        info!("cookie {}: {}", url, cookie_str);
        jar.add_cookie_str(&cookie_str, &url);
    }

    reqwest::Client::builder()
        .cookie_provider(Arc::new(jar))
        .build()
        .expect("failed creating reqwest client")
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
        if last_login.elapsed() >= Duration::from_secs(24 * 60 * 60) {
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
        let results = match args.mode {
            ApiMode::V1 => get_streams_v1(client).await,
            ApiMode::V2 => get_streams_v2(client).await,
            ApiMode::Both => get_streams(client).await,
        };

        match results {
            Ok(streams) => {
                for stream in streams {
                    let recorders = recorders.clone();

                    let cookies = cookies
                        .iter()
                        .map(|(cookie, _)| cookie.as_str())
                        .collect::<Vec<&str>>()
                        .join("; ");

                    create_recorder(stream, cookies, recorders).await
                }
            }
            Err(e) => error!("failed getting courses: {:#?}", e),
        }

        sleep(Duration::from_secs(args.poll_interval)).await;
    }
}
