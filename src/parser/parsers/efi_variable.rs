use crate::parser::DescriptionParser;
use std::convert::TryInto;

pub struct EvEfiVariableParser;
impl DescriptionParser for EvEfiVariableParser {
    fn parse_description(&self, data: Vec<u8>) -> String {
        let length =
            u64::from_le_bytes(data[16..24].try_into().expect("Failed to extract length")) as usize;

        let description_bytes = &data[32..32 + (length * 2)];

        String::from_utf8(description_bytes.to_vec())
            .expect("Invalid UTF-8 text")
            .replace('\0', "")
    }
}
