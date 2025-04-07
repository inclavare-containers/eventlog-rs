use crate::parser::DescriptionParser;

pub struct EvHandoffTableParser;

impl DescriptionParser for EvHandoffTableParser {
    fn parse_description(&self, data: Vec<u8>) -> String {
        let length =
            u8::from_le_bytes(data[0..1].try_into().expect("Failed to extract length")) as usize;
        let description_bytes = &data[1..1 + length];
        String::from_utf8(description_bytes.to_vec())
            .expect("Invalid UTF-8 text")
            .replace('\0', "")
    }
}
