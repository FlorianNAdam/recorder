use chrono::{TimeZone, Utc};
use m3u8_rs::{parse_playlist, parse_playlist_res};
use reqwest::cookie::Jar;

use std::env;
use std::sync::Arc;
use std::thread::spawn;
use std::time::Duration;
use thirtyfour::prelude::*;
use tokio::time::sleep;
use url::Url;

use rbg_client;

pub fn convert_thirtyfour_cookies(
    cookies: &[Cookie],
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let username = env::var("TUM_USERNAME")
        .expect("Environment variable TUM_USERNAME not set");

    // Read password from env
    let password = env::var("TUM_PASSWORD")
        .expect("Environment variable TUM_PASSWORD not set");

    let mut caps = DesiredCapabilities::firefox();
    caps.set_headless()?;
    let driver = WebDriver::new("http://localhost:4444", caps).await?;

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
    let jar = Jar::default();
    for (cookie_str, url) in cookie_pairs {
        jar.add_cookie_str(&cookie_str, &url);
    }

    let client = reqwest::Client::builder()
        .cookie_provider(Arc::new(jar))
        .build()?;

    let mut configuration =
        rbg_client::apis::configuration::Configuration::new();
    configuration.client = client;

    let live_courses =
        rbg_client::apis::courses_api::get_live_courses(&configuration).await?;

    if let Some(live_courses) = live_courses.live_courses {
        for live_course in &live_courses {
            println!("Course:");
            if let Some(course) = &live_course.course {
                if let Some(name) = &course.name {
                    println!("    Name: {}", name);
                }
            }

            if let Some(stream) = &live_course.stream {
                println!("    Stream:");
                if let Some(name) = &stream.name {
                    println!("        Name: {}", name);
                }
                if let Some(playlist_url) = &stream.playlist_url {
                    println!("        Playlist Url: {}", playlist_url);
                }
                if let Some(playlist_url_pres) = &stream.playlist_url_pres {
                    println!(
                        "        Playlist Url Pres: {}",
                        playlist_url_pres
                    );
                }
                if let Some(playlist_url_cam) = &stream.playlist_url_cam {
                    println!("        Playlist Url Cam: {}", playlist_url_cam);
                }
                if let Some(hls_url) = &stream.hls_url {
                    println!("        HLS Url: {}", hls_url);
                }
            }
        }
    }

    Ok(())
}
