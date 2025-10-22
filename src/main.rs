use chrono::{DateTime, TimeZone, Utc};
use clap::Parser;
use rbg_client::apis::configuration::Configuration;
use rbg_client::models::ProtobufCourseStream;
use reqwest::cookie::{CookieStore, Jar};
use tokio::fs::File;
use tokio::process::Command;

use sanitize_filename::sanitize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use thirtyfour::prelude::*;
use tokio::time::sleep;
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
    cookie_string: &String,
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

    let mut command = Command::new("ffmpeg");
    command.args(&[
        "-i",
        &stream.url.to_string(),
        "-c",
        "copy",
        "-y",
        out_file.to_str().unwrap(),
    ]);

    info!("running ffmpeg: {:?}", command);

    let mut child = command
        .stdout(Stdio::from(stdout_file.into_std().await))
        .stderr(Stdio::from(stderr_file.into_std().await))
        .spawn()?;

    let status = child.wait().await?;
    info!("ffmpeg exited with: {}", status);

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

async fn recorder_thread(stream: Stream, cookie_string: String) {
    match run_recorder(&stream, &cookie_string).await {
        Ok(()) => {
            info!("Finished recording: {} - {}", stream.course, stream.name)
        }
        Err(e) => error!(
            "Failed recording: {} - {} due to: {}",
            stream.course, stream.name, e
        ),
    }
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
    driver.quit().await?;

    let cookie_pairs =
        convert_thirtyfour_cookies(&cookies, &current_url.to_string());

    Ok(cookie_pairs)
}

#[derive(Debug)]
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

async fn get_streams(
    configuration: &Configuration,
) -> anyhow::Result<Vec<Stream>> {
    match get_streams_v2(configuration).await {
        Ok(streams) => Ok(streams),
        Err(e) => {
            warn!("failed getting courses with v2 api: {}", e);
            get_streams_v1(configuration).await
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

async fn get_streams_v1(
    configuration: &Configuration,
) -> anyhow::Result<Vec<Stream>> {
    let live_courses: Vec<StreamInfo> = configuration
        .client
        .get("https://live.rbg.tum.de/api/courses/live")
        .send()
        .await?
        .json()
        .await?;

    let mut streams = Vec::new();
    for live_course in live_courses {
        if let Some(stream) = extract_stream_v1(live_course) {
            streams.push(stream);
        }
    }
    Ok(streams)
}

async fn get_streams_v2(
    configuration: &Configuration,
) -> anyhow::Result<Vec<Stream>> {
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

fn ffmpeg_cookie_string(jar: &Jar, url: &str) -> anyhow::Result<String> {
    let url = Url::from_str(url)?;

    let cookies_opt = jar.cookies(&url);
    if cookies_opt.is_none() {
        return Ok(String::new());
    }

    let cookies_str = cookies_opt
        .unwrap()
        .to_str()?
        .to_string();

    let safe_str = cookies_str
        .replace(';', "%3B")
        .replace('"', "%22")
        .replace('\\', "\\\\");

    Ok(safe_str)
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

    /// Run browser in headless mode
    #[arg(long, default_value_t = true)]
    headless: bool,

    /// Poll interval in seconds for checking new streams
    #[arg(long, default_value_t = 10)]
    poll_interval: u64,

    /// API mode: v1, v2, or both (default: both)
    #[arg(long, value_enum, default_value_t = ApiMode::Both)]
    mode: ApiMode,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    info!("Starting RBG recorder...");

    let args = Args::parse();

    let cookie_pairs = login(
        &args.webdriver_url,
        &args.username,
        &args.password,
        args.headless,
    )
    .await?;

    let jar = Jar::default();
    for (cookie_str, url) in cookie_pairs {
        info!("cookie {}: {}", url, cookie_str);
        jar.add_cookie_str(&cookie_str, &url);
    }

    let cookie_string = ffmpeg_cookie_string(&jar, "https://live.rbg.tum.de/")?;

    let client = reqwest::Client::builder()
        .cookie_provider(Arc::new(jar))
        .build()?;

    let mut configuration = Configuration::new();
    configuration.client = client;

    let mut recorders = HashMap::new();

    loop {
        let results = match args.mode {
            ApiMode::V1 => get_streams_v1(&configuration).await,
            ApiMode::V2 => get_streams_v2(&configuration).await,
            ApiMode::Both => get_streams(&configuration).await,
        };
        match results {
            Ok(streams) => {
                for stream in streams {
                    let id = stream.id;
                    if !recorders.contains_key(&id) {
                        let cookie_string = cookie_string.clone();
                        let recorder = tokio::spawn(recorder_thread(
                            stream,
                            cookie_string,
                        ));
                        recorders.insert(id, recorder);
                    }
                }
            }
            Err(e) => error!("failed getting courses: {}", e),
        }

        sleep(Duration::from_secs(args.poll_interval)).await;
    }
}
