use crate::parser::DescriptionParser;
pub struct EvEventTagParser;
impl DescriptionParser for EvEventTagParser {
    fn parse_description(&self, data: Vec<u8>) -> String {
        let length =
            u32::from_le_bytes(data[4..8].try_into().expect("Failed to extract length")) as usize;
        let description_bytes = &data[8..8 + length];
        String::from_utf8(description_bytes.to_vec())
            .expect("Invalid UTF-8 text")
            .replace('\0', "")
    }
}
