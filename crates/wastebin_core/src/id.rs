use rand::RngExt;

use std::fmt;
use std::str::FromStr;

const CHAR_TABLE: &[char; 64] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '-', '+',
];

/// Layout of a six-character identifier: total characters, how many of those carry a full six
/// bits, and the bits the final one carries. `6 * 5 + 2` is exactly the 32 bits of an [`Id::Id32`],
/// so the final character has room for nothing more — which is what makes a spelling canonical.
const ID32_CHARS: usize = 6;
const ID32_LEADING: u32 = 5;
const ID32_LAST_BITS: u32 = 2;

/// The same for eleven-character identifiers: `6 * 10 + 4` is the 64 bits of an [`Id::Id64`].
const ID64_CHARS: usize = 11;
const ID64_LEADING: u32 = 10;
const ID64_LAST_BITS: u32 = 4;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("illegal characters")]
    IllegalCharacters,
    #[error("wrong size")]
    WrongSize,
    #[error("not a canonical identifier")]
    NotCanonical,
}

/// Write `n` as `leading` six-bit characters, most significant first, then a final character
/// holding the remaining `last_bits`.
fn encode(f: &mut fmt::Formatter<'_>, n: u64, leading: u32, last_bits: u32) -> fmt::Result {
    use fmt::Write as _;

    for i in (0..leading).rev() {
        f.write_char(table(n >> (last_bits + 6 * i)))?;
    }

    f.write_char(table(n & ((1 << last_bits) - 1)))
}

/// Read back what [`encode`] wrote, rejecting any spelling it would not have produced.
fn decode(value: &str, leading: u32, last_bits: u32) -> Result<u64, Error> {
    let leading_chars = usize::try_from(leading).unwrap_or(usize::MAX);
    let mut n: u64 = 0;

    for (pos, char) in value.chars().enumerate() {
        let bits = CHAR_TABLE
            .iter()
            .position(|c| *c == char)
            .ok_or(Error::IllegalCharacters)?;
        let bits = u64::try_from(bits).map_err(|_| Error::IllegalCharacters)?;

        if pos < leading_chars {
            n = (n << 6) | bits;
        } else {
            // The last character carries only the bits `encode` put there. Accepting a wider value
            // would fold it into bits the previous character already set, giving one identifier
            // several spellings.
            if bits >= 1 << last_bits {
                return Err(Error::NotCanonical);
            }

            n = (n << last_bits) | bits;
        }
    }

    Ok(n)
}

/// Look up the low six bits of `bits` in [`CHAR_TABLE`]. The mask bounds the index to the table's
/// 64 entries, so the fallback is unreachable.
fn table(bits: u64) -> char {
    let index = usize::try_from(bits & 0x3f).unwrap_or(0);
    CHAR_TABLE[index]
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
        match *self {
            Self::Id32(n) => encode(f, n.into(), ID32_LEADING, ID32_LAST_BITS),
            #[expect(clippy::cast_sign_loss)]
            Self::Id64(n) => encode(f, n as u64, ID64_LEADING, ID64_LAST_BITS),
        }
    }
}

impl FromStr for Id {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.len() {
            ID32_CHARS => {
                let n = decode(value, ID32_LEADING, ID32_LAST_BITS)?;
                #[expect(clippy::cast_possible_truncation)]
                Ok(Self::Id32(n as u32))
            }
            ID64_CHARS => {
                let n = decode(value, ID64_LEADING, ID64_LAST_BITS)?;
                #[expect(clippy::cast_possible_wrap)]
                Ok(Self::Id64(n as i64))
            }
            _ => Err(Error::WrongSize),
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
    fn rejects_non_canonical_spellings() {
        // Only the first four table entries fit the four bits the last character encodes.
        for (index, last) in CHAR_TABLE.iter().enumerate() {
            let id64: String = format!("aaaaaaaaaa{last}");
            let id32: String = format!("aaaaa{last}");

            assert_eq!(
                Id::from_str(&id64).is_ok(),
                index < 16,
                "11-char id ending in {last} (index {index})"
            );
            assert_eq!(
                Id::from_str(&id32).is_ok(),
                index < 4,
                "6-char id ending in {last} (index {index})"
            );
        }
    }

    #[test]
    fn parsing_round_trips_for_every_accepted_id() {
        for n in [0i64, 1, 42, -1, i64::MIN, i64::MAX, 0x0fff_ffff_ffff_ffff] {
            let rendered = Id::from(n).to_string();
            let parsed = Id::from_str(&rendered).expect("rendered id must parse");
            assert_eq!(parsed.to_string(), rendered);
            assert_eq!(parsed.to_i64(), n);
        }

        for n in [0u32, 1, 42, u32::MAX] {
            let rendered = Id::from(n).to_string();
            let parsed = Id::from_str(&rendered).expect("rendered id must parse");
            assert_eq!(parsed.to_string(), rendered);
        }
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
        assert!(Id::from_str("abDE+d").is_ok());
        assert!(Id::from_str("abDE+-1234p").is_ok());
        assert!(matches!(
            Id::from_str("#bDE+-"),
            Err(Error::IllegalCharacters)
        ));
        assert!(matches!(Id::from_str("abDE+-1"), Err(Error::WrongSize)));
        assert!(matches!(Id::from_str("abDE+"), Err(Error::WrongSize)));
        // The final character carries fewer bits than the alphabet can express, so the wider
        // spellings that used to alias onto the same id are refused.
        assert!(matches!(Id::from_str("abDE+-"), Err(Error::NotCanonical)));
        assert!(matches!(
            Id::from_str("abDE+-12345"),
            Err(Error::NotCanonical)
        ));
    }
}
