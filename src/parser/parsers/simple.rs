use crate::parser::DescriptionParser;

pub struct EvSimpleParser;

impl DescriptionParser for EvSimpleParser {
    fn parse_description(&self, data: Vec<u8>) -> String {
        String::from_utf8(data).unwrap_or(String::default())
    }
}
