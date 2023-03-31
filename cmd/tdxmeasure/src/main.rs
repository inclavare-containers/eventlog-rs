use std::fs;
extern crate eventlog_rs;

#[macro_use]
extern crate log;

use std::convert::TryFrom;

fn main() {
    env_logger::builder()
        .filter(None, log::LevelFilter::Info)
        .init();

    let path = "/sys/firmware/acpi/tables/data/CCEL".to_string();
    info!("read td: {}", path);
    let data = fs::read(path).unwrap();

    let event_log = eventlog_rs::Eventlog::try_from(data).unwrap();
    let _replayed_rtmr = event_log.replay_measurement_regiestry();

    println!("{}", event_log);
}
