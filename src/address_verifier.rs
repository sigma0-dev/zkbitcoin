use std::{
  collections::HashMap, sync::Arc, time::{Duration, UNIX_EPOCH}
};
use log::error;
use tokio::{
  spawn, sync::RwLock, time::interval,
};
use xml::reader::{EventReader, XmlEvent};

pub struct AddressVerifier {
  sanctioned_addresses: Arc<RwLock<HashMap<String, bool>>>,
  last_update: Arc<RwLock<u64>>,
}

impl AddressVerifier {
  const BTC_ID: &'static str = "344";

  pub fn new() -> Self {
    Self {
      sanctioned_addresses: Arc::new(RwLock::new(HashMap::new())),
      last_update: Arc::new(RwLock::new(Self::now())),
    }
  }

  fn now() -> u64 {
    UNIX_EPOCH.elapsed().unwrap().as_secs()
  }

  /// Periodically fetces the latest list from https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml
  /// and updates the list
  pub async fn start(&self) {
    let sanctioned_addresses = Arc::clone(&self.sanctioned_addresses);
    let last_update = Arc::clone(&self.last_update);

    spawn(async move {
      let mut interval = interval(Duration::from_secs(600));
      
      loop {
        let mut sanctioned_addresses = sanctioned_addresses.write().await;
        interval.tick().await;
        // TODO:: read the first few bytes from the remote XML file and extract the last update date.
        // If there is no fresh data we can skip the parsing of XML which is slow.
        let mut _last_update = last_update.write().await;

        let Ok(res) = reqwest::get("https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml").await else {
          error!("couldn't fetch OFAC list");
          continue;
        };
        let Ok(xml) = res.text().await else {
          error!("couldn't parse OFAC list");
          continue;
        };
        let parser: EventReader<&[u8]> = EventReader::new(xml.as_bytes());
        let mut inside_feature_elem = false;
        let mut inside_final_elem = false;

        for e in parser {
          match e {
            Ok(XmlEvent::StartElement { name, attributes, .. }) => {
              if name.local_name == "Feature" {
                if attributes.iter().any(|a| a.name.local_name == "FeatureTypeID" && a.value == Self::BTC_ID) {
                  inside_feature_elem = true;
                }
              } else if name.local_name == "VersionDetail" && inside_feature_elem {
                inside_final_elem = true;
              }
            }
            Ok(XmlEvent::Characters(value)) => {
              if inside_final_elem {
                sanctioned_addresses.insert(value, true);
              }
            }
            Ok(XmlEvent::EndElement { name, .. }) => {
              if name.local_name == "VersionDetail" && inside_feature_elem {
                inside_feature_elem = false;
                inside_final_elem = false;
              }
            }
            Err(e) => {
                error!("Error parsing xml: {e}");
                break;
            }
            _ => {}
          }
        }
      }
    }).await.unwrap();
  }
}
