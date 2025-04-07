pub mod parsers;
use lazy_static::lazy_static;
use parsers::*;
use std::collections::HashMap;

pub trait DescriptionParser: Sync + Send {
    fn parse_description(&self, data: Vec<u8>) -> String;
}

lazy_static! {
    pub static ref PARSER_MAP: HashMap<&'static str, Box<dyn DescriptionParser>> = {
        let mut map: HashMap<&'static str, Box<dyn DescriptionParser>> = HashMap::new();

        map.insert("EV_EVENT_TAG", Box::new(EvEventTagParser));
        map.insert("EV_SEPARATOR", Box::new(EvBlankParser));

        for tag in [
            "EV_EFI_VARIABLE_DRIVER_CONFIG",
            "EV_EFI_VARIABLE_BOOT",
            "EV_EFI_VARIABLE_AUTHORITY",
            "EV_EFI_VARIABLE_BOOT2",
        ] {
            map.insert(tag, Box::new(EvEfiVariableParser));
        }

        for tag in ["EV_EFI_HANDOFF_TABLES2", "EV_EFI_PLATFORM_FIRMWARE_BLOB2"] {
            map.insert(tag, Box::new(EvHandoffTableParser));
        }

        map.insert(
            "EV_EFI_BOOT_SERVICES_APPLICATION",
            Box::new(EvBootServicesAppParser),
        );

        for tag in [
            "EV_EFI_ACTION",
            "EV_IPL",
            "EV_POST_CODE",
            "EV_ACTION",
            "EV_PLATFORM_CONFIG_FLAGS",
            "EV_COMPACT_HASH",
            "EV_OMIT_BOOT_DEVICE_EVENTS",
            "EV_EFI_HCRTM_EVENT",
        ] {
            map.insert(tag, Box::new(EvSimpleParser));
        }

        map
    };
}
