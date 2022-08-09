use std::fs;
extern crate eventlog_rs;

#[macro_use]
extern crate log;

use std::convert::TryFrom;

fn main() {
    env_logger::builder()
        .filter(None, log::LevelFilter::Info)
        .init();
    let mut event_data = vec![];

    let path = "/sys/firmware/acpi/tables/TDEL".to_string();
    info!("read td: {}", path);
    let data = fs::read(path).unwrap();
    event_data.push(data);

    let path = "/sys/firmware/acpi/tables/data/TDEL".to_string();
    info!("read td: {}", path);
    let data = fs::read(path).unwrap();
    event_data.push(data);

    let event_log_info = eventlog_rs::EventlogInfo::try_from(event_data[0].clone()).unwrap();
    let event_log = eventlog_rs::Eventlog::try_from(event_data[1].clone()).unwrap();
    let replayed_rtmr = event_log.replay_measurement_regiestry();

    println!("{:?}", event_log_info);
    println!("\n\n--------------------------------------------------------\n\n");
    println!("{:?}", event_log);
    println!("\n\n--------------------------------------------------------\n\n");
    println!("{:?}", replayed_rtmr);
}
