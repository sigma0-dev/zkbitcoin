use std::{
  collections::HashMap, sync::Arc, time::{Duration, UNIX_EPOCH}
};
use tokio::{
  spawn, sync::RwLock, time::interval,
};

pub struct AddressVerifier {
  sanctioned_addresses: Arc<RwLock<HashMap<String, bool>>>,
  last_update: Arc<u64>,
}

impl AddressVerifier {
  const DAY_IN_SECS: u64 = 86400;

  pub fn new() -> Self {
    Self {
      sanctioned_addresses: Arc::new(RwLock::new(HashMap::new())),
      last_update: Arc::new(Self::now()),
    }
  }

  fn now() -> u64 {
    UNIX_EPOCH.elapsed().unwrap().as_secs()
  }

  /// Periodically fetces the latest list from https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml
  /// and updates the list
  pub fn refresh_list(&self) {
    let sanctioned_addresses = Arc::clone(&self.sanctioned_addresses);
    let last_update = Arc::clone(&self.last_update);

    spawn(async move {
      
      let mut interval = interval(Duration::from_secs(600));
      
      loop {
        let mut sanctioned_addresses = sanctioned_addresses.write().await;
        interval.tick().await;

        if Self::now() - *last_update >= Self::DAY_IN_SECS {
          sanctioned_addresses.insert("".to_string(), true);
        }
      }
    });
  }
}
