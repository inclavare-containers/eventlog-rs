pub mod blank;
pub mod boot_services_app;
pub mod efi_variable;
pub mod event_tag;
pub mod handoff_table;
pub mod simple;

pub use blank::*;
pub use boot_services_app::*;
pub use efi_variable::*;
pub use event_tag::*;
pub use handoff_table::*;
pub use simple::*;
