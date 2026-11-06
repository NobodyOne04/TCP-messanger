//! Session protector: both peers share a "hash" (a string of digits) and an
//! initial session key (10 digits). After every message the key is rotated
//! with [`SessionProtector::next_session_key`]; the server rejects any message
//! whose key doesn't match the one it expects.
//!
//! Note: this is a lab-style scheme for detecting session hijacking, not
//! cryptography. The hash travels in plaintext during the handshake.

use std::fmt;

use rand::Rng;

/// Length of every session key, in digits.
pub const KEY_LEN: usize = 10;
/// Number of digits in a freshly generated hash.
pub const HASH_LEN: usize = 5;
/// Upper bound accepted from the network (keeps arithmetic far from overflow).
pub const MAX_HASH_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectorError {
    InvalidHash(String),
    InvalidKey(String),
}

impl fmt::Display for ProtectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtectorError::InvalidHash(h) => {
                write!(f, "invalid hash {h:?}: expected 1..={MAX_HASH_LEN} digits")
            }
            ProtectorError::InvalidKey(k) => {
                write!(
                    f,
                    "invalid session key {k:?}: expected exactly {KEY_LEN} digits"
                )
            }
        }
    }
}

impl std::error::Error for ProtectorError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProtector {
    hash: Vec<u8>, // digits 0..=9
}

impl SessionProtector {
    pub fn new(hash: &str) -> Result<Self, ProtectorError> {
        let valid = !hash.is_empty()
            && hash.len() <= MAX_HASH_LEN
            && hash.bytes().all(|b| b.is_ascii_digit());
        if !valid {
            return Err(ProtectorError::InvalidHash(hash.to_string()));
        }
        Ok(Self {
            hash: hash.bytes().map(|b| b - b'0').collect(),
        })
    }

    pub fn hash(&self) -> String {
        self.hash.iter().map(|d| char::from(b'0' + d)).collect()
    }

    /// Derive the key that must accompany the next message.
    pub fn next_session_key(&self, key: &str) -> Result<String, ProtectorError> {
        validate_key(key)?;
        let total: u64 = self.hash.iter().map(|&d| step(key, d)).sum();
        let digits = total.to_string();
        let head = &digits[..digits.len().min(KEY_LEN)];
        Ok(format!("{head:0>KEY_LEN$}"))
    }
}

pub fn validate_key(key: &str) -> Result<(), ProtectorError> {
    if key.len() == KEY_LEN && key.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(ProtectorError::InvalidKey(key.to_string()))
    }
}

/// One term of the key derivation, selected by a hash digit.
/// `key` must already be validated (10 ASCII digits).
fn step(key: &str, digit: u8) -> u64 {
    let num = |s: &str| s.parse::<u64>().expect("validated digits");
    match digit {
        1 => num(&key[..5]) % 97,
        2 => num(&key.chars().rev().collect::<String>()),
        3 => num(&format!("{}{}", &key[KEY_LEN - 5..], &key[..5])),
        4 => key.bytes().skip(1).take(8).map(|b| u64::from(b) + 41).sum(),
        5 => key.bytes().map(|b| u64::from(b ^ 43)).sum(),
        d => num(key) + u64::from(d),
    }
}

/// Random hash of `HASH_LEN` digits, each uniformly in 1..=6.
pub fn generate_hash() -> String {
    let mut rng = rand::thread_rng();
    (0..HASH_LEN)
        .map(|_| char::from(b'0' + rng.gen_range(1..=6)))
        .collect()
}

/// Random initial session key of `KEY_LEN` digits, each uniformly in 1..=9.
pub fn generate_session_key() -> String {
    let mut rng = rand::thread_rng();
    (0..KEY_LEN)
        .map(|_| char::from(b'0' + rng.gen_range(1..=9)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The original (v0.1) implementation, kept verbatim in spirit as an oracle
    /// to prove the rewrite derives exactly the same keys.
    #[allow(clippy::all)]
    mod legacy {
        pub fn next_session_key(hash: &str, session_key: &String) -> String {
            let mut result = 0;
            for idx in 0..hash.len() {
                let d = hash.chars().nth(idx).unwrap().to_digit(10).unwrap() as i64;
                result += calc_hash(session_key, d).parse::<i64>().unwrap();
            }
            let result = if result.to_string().len() > 10 {
                result.to_string()[0..10].to_string()
            } else {
                result.to_string()
            };
            let result = format!("{}{}", "0".repeat(10), result);
            result[result.len() - 10..result.len()].to_string()
        }

        fn calc_hash(session_key: &String, val: i64) -> String {
            let mut result = "".to_string();
            match val {
                1 => {
                    result = format!("00{}", session_key[0..5].parse::<i64>().unwrap() % 97);
                    result[result.len() - 2..].to_string()
                }
                2 => {
                    for i in 1..session_key.len() {
                        result = format!(
                            "{}{}",
                            result,
                            session_key.chars().nth(session_key.len() - i).unwrap()
                        );
                    }
                    format!("{}{}", result, session_key.chars().nth(0).unwrap())
                }
                3 => format!(
                    "{}{}",
                    &session_key[session_key.len() - 5..],
                    &session_key[0..5]
                ),
                4 => {
                    let mut num = 0;
                    for i in 1..9 {
                        num += session_key.chars().nth(i).unwrap() as i64 + 41
                    }
                    num.to_string()
                }
                5 => {
                    let mut num = 0;
                    for i in 0..session_key.len() {
                        let ch = session_key.chars().nth(i).unwrap() as i64 ^ 43;
                        let ch = if !(ch as u8 as char).is_digit(10) {
                            ch.to_string()
                        } else {
                            (ch as u8 as char).to_string()
                        };
                        num += ch.parse::<i64>().unwrap();
                    }
                    num.to_string()
                }
                _ => (session_key.parse::<i64>().unwrap() + val).to_string(),
            }
        }
    }

    fn random_digits(rng: &mut impl Rng, len: usize, lo: u8) -> String {
        (0..len)
            .map(|_| char::from(b'0' + rng.gen_range(lo..=9)))
            .collect()
    }

    #[test]
    fn matches_legacy_implementation() {
        let mut rng = rand::thread_rng();
        for _ in 0..20_000 {
            let len = rng.gen_range(1..=8);
            let hash = random_digits(&mut rng, len, 0);
            let mut key = random_digits(&mut rng, KEY_LEN, 0);
            let p = SessionProtector::new(&hash).unwrap();
            // Follow a short chain so derived (zero-padded) keys are covered too.
            for _ in 0..3 {
                let expected = legacy::next_session_key(&hash, &key);
                let actual = p.next_session_key(&key).unwrap();
                assert_eq!(actual, expected, "hash={hash} key={key}");
                key = actual;
            }
        }
    }

    #[test]
    fn rejects_bad_input() {
        assert!(SessionProtector::new("").is_err());
        assert!(SessionProtector::new("12a").is_err());
        assert!(SessionProtector::new(&"1".repeat(MAX_HASH_LEN + 1)).is_err());
        let p = SessionProtector::new("12345").unwrap();
        assert!(p.next_session_key("123").is_err());
        assert!(p.next_session_key("12345678901").is_err());
        assert!(p.next_session_key("12345abcde").is_err());
    }

    #[test]
    fn generators_produce_valid_values() {
        for _ in 0..1000 {
            let h = generate_hash();
            assert_eq!(h.len(), HASH_LEN);
            assert!(h.bytes().all(|b| (b'1'..=b'6').contains(&b)));
            let k = generate_session_key();
            assert!(validate_key(&k).is_ok());
            assert!(k.bytes().all(|b| (b'1'..=b'9').contains(&b)));
        }
    }
}
