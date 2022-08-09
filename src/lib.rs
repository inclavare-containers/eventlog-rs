use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use enums::{EVENTLOG_TYPES, TCG_ALGORITHMS};
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use std::convert::TryFrom;

const RTMR_LENGTH_BY_BYTES: usize = 48;

mod enums;

#[macro_use]
extern crate log;

#[derive(Debug)]
pub struct EventlogInfo {
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: String,
    pub log_length: u64,
    pub base_address: u64,
}

impl TryFrom<Vec<u8>> for EventlogInfo {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(EventlogInfo {
            revision: data[8],
            checksum: data[9],
            oem_id: String::from(std::str::from_utf8(&data[10..16])?),
            log_length: (&data[40..48]).read_u64::<LittleEndian>()?,
            base_address: (&data[48..56]).read_u64::<LittleEndian>()?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Eventlog {
    pub log: Vec<EventlogEntry>,
}

#[derive(Debug, Clone)]
pub struct EventlogEntry {
    pub target_measurement_registry: u32,
    pub event_type: String,
    pub digests: Vec<ElDigest>,
    pub event_desc: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ElDigest {
    pub algorithm: String,
    pub digest: Vec<u8>,
}

impl Eventlog {
    pub fn replay_measurement_regiestry(&self) -> HashMap<u32, Vec<u8>> {
        // result dictionary for classifying event logs by rtmr index
        // the key is a integer, which represents rtmr index
        // the value is a list of event log entries whose rtmr index is equal to its related key
        let mut event_logs_by_mr_index: HashMap<u32, Vec<EventlogEntry>> = HashMap::new();

        let mut result: HashMap<u32, Vec<u8>> = HashMap::new();

        for log_entry in self.log.iter() {
            match event_logs_by_mr_index.get_mut(&log_entry.target_measurement_registry) {
                Some(logs) => logs.push(log_entry.clone()),
                None => {
                    event_logs_by_mr_index.insert(
                        log_entry.target_measurement_registry,
                        vec![log_entry.clone()],
                    );
                }
            }
        }

        for (mr_index, log_set) in event_logs_by_mr_index.iter() {
            let mut mr_value = [0; RTMR_LENGTH_BY_BYTES];

            for log in log_set.iter() {
                let digest = &log.digests[0].digest;
                let mut sha384_algo = Sha384::new();
                sha384_algo.update(&mr_value);
                sha384_algo.update(digest.as_slice());
                mr_value.copy_from_slice(sha384_algo.finalize().as_slice());
            }
            result.insert(mr_index.clone(), mr_value.to_vec());
        }

        result
    }
}

impl TryFrom<Vec<u8>> for Eventlog {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        let mut index = 0;
        let mut event_log: Vec<EventlogEntry> = Vec::new();
        let mut digest_size_map: HashMap<u16, u16> = HashMap::new();

        while index < data.len() as usize {
            let target_measurement_registry =
                (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;
            if target_measurement_registry == 0xFFFFFFFF {
                break;
            }

            let event_type_num = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;
            let event_type = match EVENTLOG_TYPES.get(&event_type_num) {
                Some(type_name) => type_name.to_string(),
                None => format!("UNKOWN_TYPE: {:x}", &event_type_num),
            };

            if event_type == "EV_NO_ACTION".to_string() {
                index += 48;
                let algo_number = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
                index += 4;
                for _ in 0..algo_number {
                    digest_size_map.insert(
                        (&data[index..(index + 2)]).read_u16::<LittleEndian>()?,
                        (&data[(index + 2)..(index + 4)]).read_u16::<LittleEndian>()?,
                    );
                    index += 4;
                }
                let vendor_size = data[index];
                index += vendor_size as usize + 1;
                continue;
            }

            let digest_count = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;
            let mut digests: Vec<ElDigest> = Vec::new();
            for _ in 0..digest_count {
                let digest_algo_num = (&data[index..(index + 2)]).read_u16::<LittleEndian>()?;
                index += 2;
                let algorithm = match TCG_ALGORITHMS.get(&digest_algo_num) {
                    Some(digest_algo_name) => digest_algo_name.to_string(),
                    None => format!("UNKOWN_ALGORITHM: {:x}", &digest_algo_num),
                };
                let digest_size = digest_size_map
                    .get(&digest_algo_num)
                    .ok_or(anyhow!(
                        "Internal Error: get digest size failed when parse eventlog entry, digest_algo_num: {:?}", &digest_algo_num
                    ))?
                    .to_owned() as usize;
                let digest = data[index..(index + digest_size)].to_vec();
                index += digest_size;
                digests.push(ElDigest { algorithm, digest });
            }

            let event_desc_size = (&data[index..(index + 4)]).read_u32::<LittleEndian>()? as usize;
            index += 4;
            let event_desc = data[index..(index + event_desc_size)].to_vec();
            index += event_desc_size;

            let eventlog_entry = EventlogEntry {
                target_measurement_registry,
                event_type,
                digests,
                event_desc,
            };

            debug!("{:?}\n\n", &eventlog_entry);

            event_log.push(eventlog_entry)
        }

        Ok(Eventlog { log: event_log })
    }
}
