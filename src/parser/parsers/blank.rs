use crate::parser::DescriptionParser;
pub struct EvBlankParser;
impl DescriptionParser for EvBlankParser {
    fn parse_description(&self, _data: Vec<u8>) -> String {
        String::default()
    }
}
