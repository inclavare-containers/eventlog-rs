use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use core::fmt;
use enums::{EVENTLOG_TYPES, TCG_ALGORITHMS};
use sha2::digest::FixedOutput;
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;
use std::convert::TryFrom;

mod bios_eventlog;
mod enums;

pub use bios_eventlog::BiosEventlog;
pub mod read;

#[derive(Clone)]
pub struct Eventlog {
    pub log: Vec<EventlogEntry>,
}

impl fmt::Display for Eventlog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut parsed_el = String::default();
        for event_entry in self.log.clone() {
            parsed_el = format!(
                "{}\nEvent Entry:\n\tPCR: {}\n\tEvent Type id: {}\n\tEvent Type: {}\n\tDigest Algorithm: {}\n\tDigest: {}\n\tEvent Desc: {}\n",
                parsed_el,
                event_entry.target_measurement_registry,
                format!("0x{:08X}", event_entry.event_type_id),
                event_entry.event_type,
                event_entry.digests[0].algorithm,
                hex::encode(event_entry.digests[0].digest.clone()),
                String::from_utf8(event_entry.event_desc.clone())
                    .unwrap_or_else(|_| hex::encode(event_entry.event_desc.clone())),
            );
        }

        write!(f, "{parsed_el}")
    }
}

#[derive(Clone)]
pub struct EventlogEntry {
    pub target_measurement_registry: u32,
    pub event_type_id: u32,
    pub event_type: String,
    pub digests: Vec<ElDigest>,
    pub event_desc: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ElDigest {
    pub algorithm: String,
    pub digest: Vec<u8>,
}

pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl HashAlgorithm {
    pub fn digest_length(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
        }
    }

    pub fn hash<'a, I>(&self, data: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a [u8]>,
    {
        match self {
            HashAlgorithm::Sha256 => self.accumulate_hash::<Sha256, _>(data),
            HashAlgorithm::Sha384 => self.accumulate_hash::<Sha384, _>(data),
        }
    }

    fn accumulate_hash<'a, D: Digest + FixedOutput, I>(&self, data: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a [u8]>,
    {
        let mut hasher = D::new();
        for slice in data {
            Digest::update(&mut hasher, slice);
        }

        let res = hasher.finalize().to_vec();
        res
    }
}

impl Eventlog {
    /// Replay measurement registers with event logs.
    /// If not provided the input mapping, the result will be a dictionary whose key is pcr
    /// index and value is the measurement value.
    ///
    /// If provided the input mapping, the PCRs with index specified by the mapping will be
    /// mapped to the value (which is usually the RTMR index). The result dictionary will
    /// be a dictionary whose key is the RTMR index and value is the measurement value.
    pub fn replay_measurement_registry<F>(
        &self,
        hash_algorithm: HashAlgorithm,
        pcr_to_rtmr_mapping: F,
    ) -> HashMap<u32, Vec<u8>>
    where
        F: Fn(u32) -> u32,
    {
        let mut result: HashMap<u32, Vec<u8>> = HashMap::new();
        for log_entry in &self.log {
            let pcr_index = log_entry.target_measurement_registry;
            let rtmr_index = pcr_to_rtmr_mapping(pcr_index);
            if !result.contains_key(&rtmr_index) {
                result.insert(rtmr_index, vec![0; hash_algorithm.digest_length()]);
            }

            let mr_value = hash_algorithm
                .hash([&result[&rtmr_index], log_entry.digests[0].digest.as_slice()].into_iter());

            let value = result.get_mut(&rtmr_index).unwrap();
            *value = mr_value;
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
            let stop_flag = (&data[index..(index + 8)]).read_u64::<LittleEndian>()?;
            let target_measurement_registry =
                (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;

            let event_type_num = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;
            let event_type = match EVENTLOG_TYPES.get(&event_type_num) {
                Some(type_name) => type_name.to_string(),
                None => format!("UNKNOWN_TYPE: {:x}", &event_type_num),
            };

            let event_type_id = event_type_num;
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

            if stop_flag == 0xFFFFFFFFFFFFFFFF || stop_flag == 0x0000000000000000 {
                break;
            }

            let digest_count = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;
            let mut digests: Vec<ElDigest> = Vec::new();
            for _ in 0..digest_count {
                let digest_algo_num = (&data[index..(index + 2)]).read_u16::<LittleEndian>()?;
                index += 2;
                let algorithm = match TCG_ALGORITHMS.get(&digest_algo_num) {
                    Some(digest_algo_name) => digest_algo_name.to_string(),
                    None => format!("UNKNOWN_ALGORITHM: {:x}", &digest_algo_num),
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
                event_type_id,
                event_type,
                digests,
                event_desc,
            };

            event_log.push(eventlog_entry)
        }

        Ok(Eventlog { log: event_log })
    }
}
