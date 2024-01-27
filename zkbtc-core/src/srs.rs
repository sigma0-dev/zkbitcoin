use std::path::PathBuf;

use log::info;
use tokio::{fs::File, io::AsyncWriteExt};
use tokio_stream::StreamExt;

use crate::zkbitcoin_folder;

//
// Constants
//

/// The hash of the [SRS_URL]. Taken from https://github.com/iden3/snarkjs#7-prepare-phase-2
const SRS_HASH: &str = "1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922";

/// The URL to download the SRS. Taken from https://github.com/iden3/snarkjs#7-prepare-phase-2
const SRS_URL: &str = "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau";

/// The max circuit size that can be created with the hardcoded SRS.
const SRS_SIZE: usize = 16;

//
// SRS Logic
//

/// Downloads the SRS file into the local zkBitcoin folder
pub async fn download_srs() -> PathBuf {
    // create zkbitcoin dir if it doesn't exist
    let zkbitcoin_dir = zkbitcoin_folder();
    let srs_path = zkbitcoin_dir.join("srs_28.ptau");

    // download srs path if it doesn't exists
    if srs_path.exists() {
        return srs_path;
    }

    info!("downloading srs...");
    let mut file = File::create(&srs_path).await.unwrap();
    let mut stream = reqwest::get(SRS_URL).await.unwrap().bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.unwrap();
        file.write_all(&chunk).await.unwrap();
    }

    file.flush().await.unwrap();

    info!(
        "Downloaded SRS for 2^{SRS_SIZE} circuits at {}",
        srs_path.to_string_lossy()
    );

    srs_path
}

/// Returns the local path to the SRS file.
pub async fn srs_path() -> PathBuf {
    // download if necessary
    let srs_path = download_srs().await;

    // always check integrity of file
    let hash = sha256::try_digest(&srs_path).unwrap();
    assert_eq!(hash, SRS_HASH);

    //
    srs_path
}
