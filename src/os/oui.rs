use std::collections::HashMap;

pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    // Normalize: uppercase, remove separators
    let clean = mac.to_uppercase().replace(":", "").replace("-", "");
    if clean.len() < 6 {
        return None;
    }

    let prefix = &clean[0..6];

    // Minimal but high‑value OUI table
    static OUI: phf::Map<&'static str, &'static str> = phf::phf_map! {
        // Apple
        "F01898" => "Apple",
        "A483E7" => "Apple",
        "A4B1C1" => "Apple",
        "B827EB" => "Apple",

        // AVM FritzBox
        "DC15C8" => "AVM GmbH",
        "001A4F" => "AVM GmbH",

        // Intel
        "3C970E" => "Intel",
        "F4B7E2" => "Intel",

        // Realtek
        "00E04C" => "Realtek",
        "B0C420" => "Realtek",

        // Microsoft
        "00155D" => "Microsoft",

        // Ubiquiti
        "F09FC2" => "Ubiquiti",
        "24A43C" => "Ubiquiti",

        // Synology
        "001132" => "Synology",
        

        // QNAP
        "245EBE" => "QNAP",
        "00089B" => "QNAP",
    };

    OUI.get(prefix).copied()
}
