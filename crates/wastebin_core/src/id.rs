use rand::RngExt;

use std::fmt;
use std::str::FromStr;

const CHAR_TABLE: &[char; 64] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '-', '+',
];

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("illegal characters")]
    IllegalCharacters,
    #[error("wrong size")]
    WrongSize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Id {
    /// Six-character identifiers.
    Id32(u32),
    /// Eleven-character identifiers.
    Id64(i64),
}

impl Id {
    /// Generate a new random [`Id`]. According to the [`rand::rng()`] documentation this should be
    /// fast and not require additional an `spawn_blocking()` call.
    #[must_use]
    pub fn rand() -> Self {
        Self::Id64(rand::rng().random::<i64>())
    }

    /// Return i64 representation for database storage purposes.
    #[must_use]
    pub fn to_i64(self) -> i64 {
        match self {
            Self::Id32(n) => n.into(),
            Self::Id64(n) => n,
        }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write as _;

        match self {
            Self::Id32(n) => {
                for shift in [26, 20, 14, 8, 2] {
                    f.write_char(CHAR_TABLE[((n >> shift) & 0x3f) as usize])?;
                }

                f.write_char(CHAR_TABLE[(n & 0x3) as usize])
            }
            #[expect(clippy::cast_sign_loss)]
            Self::Id64(n) => {
                for shift in [58, 52, 46, 40, 34, 28, 22, 16, 10, 4] {
                    f.write_char(CHAR_TABLE[((n >> shift) & 0x3f) as usize])?;
                }

                f.write_char(CHAR_TABLE[(n & 0xf) as usize])
            }
        }
    }
}

impl FromStr for Id {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() == 6 {
            let mut n: u32 = 0;

            for (pos, char) in value.chars().enumerate() {
                #[expect(clippy::cast_possible_truncation)]
                let bits: u32 = CHAR_TABLE
                    .iter()
                    .position(|c| *c == char)
                    .ok_or(Error::IllegalCharacters)? as u32;

                if pos < 5 {
                    n = (n << 6) | bits;
                } else {
                    n = (n << 2) | bits;
                }
            }

            Ok(Self::Id32(n))
        } else if value.len() == 11 {
            let mut n: i64 = 0;

            for (pos, char) in value.chars().enumerate() {
                #[expect(clippy::cast_possible_wrap)]
                let bits: i64 = CHAR_TABLE
                    .iter()
                    .position(|c| *c == char)
                    .ok_or(Error::IllegalCharacters)? as i64;

                if pos < 10 {
                    n = (n << 6) | bits;
                } else {
                    n = (n << 4) | bits;
                }
            }

            Ok(Self::Id64(n))
        } else {
            Err(Error::WrongSize)
        }
    }
}

impl From<u32> for Id {
    fn from(n: u32) -> Self {
        Self::Id32(n)
    }
}

impl From<i64> for Id {
    fn from(n: i64) -> Self {
        Self::Id64(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_i64_to_id_and_back() {
        let id = Id::from(0u32);
        assert_eq!(id.to_string(), "aaaaaa");
        assert_eq!(id.to_i64(), 0);

        let id = Id::from(0i64);
        assert_eq!(id.to_string(), "aaaaaaaaaaa");
        assert_eq!(id.to_i64(), 0);

        let id = Id::from(0xffff_ffff_u32);
        assert_eq!(id.to_string(), "+++++d");
        assert_eq!(id.to_i64(), 0xffff_ffff);

        let id = Id::from(0xfff_ffff_ffff_ffff_i64);
        assert_eq!(id.to_string(), "d+++++++++p");
        assert_eq!(id.to_i64(), 0xfff_ffff_ffff_ffff);
    }

    #[test]
    fn convert_string_to_id_and_back() {
        let id = Id::from_str("bJZCna").unwrap();
        assert_eq!(id.to_i64(), 104_651_828);
        assert_eq!(id.to_string(), "bJZCna");

        let id = Id::from_str("eVI4Z48hybf").unwrap();
        assert_eq!(id.to_i64(), 1_367_045_688_504_311_829);
        assert_eq!(id.to_string(), "eVI4Z48hybf");
    }

    #[test]
    fn conversion_failures() {
        assert!(Id::from_str("abDE+-").is_ok());
        assert!(Id::from_str("abDE+-12345").is_ok());
        assert!(matches!(
            Id::from_str("#bDE+-"),
            Err(Error::IllegalCharacters)
        ));
        assert!(matches!(Id::from_str("abDE+-1"), Err(Error::WrongSize)));
        assert!(matches!(Id::from_str("abDE+"), Err(Error::WrongSize)));
    }
}
