//! Deterministic system-context rules used by the upstream PID generator.
#![cfg_attr(not(test), allow(dead_code))]
use super::binary::invalid;
use std::io;
pub fn mpc(
    build: u32,
    edition: &str,
    architecture: &str,
    setup: Option<&str>,
) -> io::Result<String> {
    let default = if build >= 10240 {
        "03612"
    } else if build >= 9600 {
        "06401"
    } else if build >= 9200 {
        "05426"
    } else {
        "55041"
    };
    let arch = architecture.to_ascii_uppercase();
    let arch = if arch == "AMD64" { "X64" } else { &arch };
    let prefix = format!("{arch}.{edition}=");
    let selected = if edition.contains(';') {
        None
    } else {
        setup
            .and_then(|text| text.lines().find(|line| line.contains(&prefix)))
            .and_then(|line| line.split('=').nth(1))
            .map(str::trim)
    }
    .unwrap_or(default);
    if selected.len() != 5 || !selected.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("invalid MPC in setup.cfg"));
    }
    Ok(selected.into())
}
pub fn day_of_year(year: u32, month: u32, day: u32) -> io::Result<u32> {
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
        return Err(invalid("invalid PID date"));
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > months[month as usize - 1] {
        return Err(invalid("invalid PID date"));
    }
    Ok(months[..month as usize - 1].iter().sum::<u32>() + day)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mpc_build_boundaries_and_setup_overrides_follow_upstream() {
        for (build, expected) in [
            (7601, "55041"),
            (9200, "05426"),
            (9600, "06401"),
            (10240, "03612"),
        ] {
            assert_eq!(mpc(build, "Professional", "AMD64", None).unwrap(), expected);
        }
        assert_eq!(
            mpc(
                26100,
                "Professional",
                "AMD64",
                Some("X86.Professional=00001\nX64.Professional= 12345 \n")
            )
            .unwrap(),
            "12345"
        );
        assert_eq!(
            mpc(26100, "A;B", "AMD64", Some("X64.A;B=00001")).unwrap(),
            "03612"
        );
        assert!(mpc(26100, "A", "AMD64", Some("X64.A=oops")).is_err());
    }
    #[test]
    fn ordinal_date_handles_leap_years_centuries_and_invalid_dates() {
        assert_eq!(day_of_year(2000, 3, 1).unwrap(), 61);
        assert_eq!(day_of_year(1900, 3, 1).unwrap(), 60);
        assert_eq!(day_of_year(2024, 12, 31).unwrap(), 366);
        assert_eq!(day_of_year(2026, 12, 31).unwrap(), 365);
        for (y, m, d) in [
            (0, 1, 1),
            (2026, 0, 1),
            (2026, 13, 1),
            (2026, 2, 29),
            (2026, 4, 31),
            (2026, 1, 0),
        ] {
            assert!(day_of_year(y, m, d).is_err());
        }
    }
}
