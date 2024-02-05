use anyhow::Result;
use log::warn;
use reqwest::Client;
use serde::Deserialize;
use versions::Versioning;

const RELEASES_URL: &str = "https://api.github.com/repos//sigma0-xyz/zkbitcoin/releases/latest";

#[derive(Deserialize, Debug)]
struct Release {
    url: String,
    tag_name: String,
}

async fn fetch_latest_version() -> Result<Release> {
    let client = Client::new();

    let release = client
        .get(RELEASES_URL)
        .header("User-Agent", "zkbitcoin cli")
        .send()
        .await?
        .json::<Release>()
        .await?;

    Ok(release)
}

pub async fn check_version() -> Result<()> {
    let current_version = Versioning::new(env!("CARGO_PKG_VERSION"));
    let latest_release = fetch_latest_version().await?;
    let latest_version = Versioning::new(&latest_release.tag_name.replace('v', ""));

    if current_version < latest_version {
        warn!(
            "You are using an old version. Please download the latest version: {}",
            latest_release.url
        )
    }

    Ok(())
}
