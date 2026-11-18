// SPDX-License-Identifier: LGPL-2.1-or-later

//! Serves the fake `wpa_supplicant` on a bus until killed.
//!
//! Usage: `kestrel-fake-wpa ADDRESS STATION...` (honours `KESTREL_BUS_UID`).

use kestrel_wlan_wpa::testkit::FakeWpa;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let address = args
        .next()
        .ok_or("usage: kestrel-fake-wpa ADDRESS STATION...")?;
    let stations: Vec<String> = args.collect();
    let stations: Vec<&str> = stations.iter().map(String::as_str).collect();
    let connection = kestrel_api::bus::connect(&address).await?;
    let _fake = FakeWpa::serve(connection, &stations).await?;
    println!("ready");
    std::future::pending::<()>().await;
    Ok(())
}
