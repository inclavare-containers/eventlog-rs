use crate::parser::DescriptionParser;
pub struct EvBootServicesAppParser;

impl DescriptionParser for EvBootServicesAppParser {
    fn parse_description(&self, data: Vec<u8>) -> String {
        // ImageLocationInMemory + ImageLengthInMemory + ImageLinkTimeAddress (24) and 8 for length
        let length_of_device_path = u64::from_le_bytes(data[24..32].try_into().unwrap());

        // Calculate the start of the device path and ensure data length
        let device_path_start = 32;
        let device_path_end_header = 4;
        let device_path_end =
            device_path_start + (length_of_device_path - device_path_end_header) as usize;

        assert!(
            data.len() >= device_path_end,
            "Data too short for the device path"
        );

        let device_path_bytes = &data[device_path_start..device_path_end];

        get_nested_data(&device_path_bytes).unwrap_or_else(String::default)
    }
}

fn get_nested_data(device_path_bytes: &[u8]) -> Option<String> {
    let efi_type = u8::from_le_bytes(device_path_bytes[0..1].try_into().unwrap());
    let efi_sub_type = u8::from_le_bytes(device_path_bytes[1..2].try_into().unwrap());
    let efi_length = u16::from_le_bytes(device_path_bytes[2..4].try_into().unwrap()) as usize;
    let vendor_data_raw = &device_path_bytes[4..efi_length];

    let device_path = &device_path_bytes[efi_length..];

    // https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#generic-device-path-node-structure
    if device_path.len() == 0 {
        return if efi_type == 4 && efi_sub_type == 3 {
            Some(hex::encode(vendor_data_raw))
        } else if efi_type == 4 && efi_sub_type == 4 {
            Some(recover_string(vendor_data_raw))
        } else {
            None
        };
    }

    get_nested_data(&device_path)
}

fn recover_string(vendor_data_raw: &[u8]) -> String {
    let device_path: Vec<u16> = vendor_data_raw
        .chunks(2)
        .map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap()))
        .collect();

    let device_path_str: String = device_path
        .iter()
        .map(|&c| std::char::from_u32(c as u32).unwrap_or(char::default()))
        .collect();

    device_path_str
}
