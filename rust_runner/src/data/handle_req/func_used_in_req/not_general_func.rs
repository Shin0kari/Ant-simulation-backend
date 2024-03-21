use serde_json::Value;
use std::fs;

pub fn check_access(address: &str) -> bool {
    let check_data = match fs::read_to_string("access_check.json") {
        Ok(data_file) => data_file,
        Err(error) => {
            println!("file not found: {:?}", error);
            return false;
        }
    };

    match serde_json::from_str(&check_data) {
        Ok(val) => {
            let data_value: Value = val;
            let check = data_value[address.split(':').next().unwrap_or_default()]["state"]
                .as_str()
                .unwrap_or_default();
            matches!(check, "+")
        }
        _ => false,
    }
}
