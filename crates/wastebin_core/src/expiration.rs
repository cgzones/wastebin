use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to parse number: {0}")]
    ParsingNumber(std::num::ParseIntError),
    #[error("illegal modifier, only =d allowed")]
    IllegalModifier,
    #[error("multiple default values")]
    MultipleDefaults,
    #[error("illegal magnitude, only s, m, h, d, w, M and y allowed")]
    IllegalMagnitude,
    #[error("value with magnitude overflows")]
    Overflow,
    #[error("duplicate expiration values")]
    DuplicateExpirations,
}

/// Single expiration value that can be the default in a set of values.
#[derive(Clone, Copy, Debug, Ord, Eq, PartialEq, PartialOrd)]
pub struct Expiration {
    pub duration: Duration,
    pub default: bool,
}

/// Coarse unit of an [`Expiration`] duration component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Year,
    Month,
    Week,
    Day,
    Hour,
    Minute,
    Second,
}

impl Expiration {
    /// Break the duration into whole `(value, unit)` components, largest unit first.
    #[must_use]
    pub fn components(&self) -> Vec<(u64, Unit)> {
        self.breakdown()
            .map(|(value, (_, _, unit, ..))| (value, unit))
            .collect()
    }

    /// Whole multiples of each [`UNITS`] row the duration breaks into, largest unit first. Rows
    /// that fit zero times are skipped.
    fn breakdown(&self) -> impl Iterator<Item = (u64, UnitRow)> {
        let mut secs = self.duration.as_secs();

        UNITS.into_iter().filter_map(move |row| {
            let value = secs / row.1;
            (value > 0).then(|| {
                secs %= row.1;
                (value, row)
            })
        })
    }
}

/// Multiple expiration values in ordered fashion.
pub struct ExpirationSet(Vec<Expiration>);

/// Rough number of seconds in a month
const MONTH_SECS: u64 = 30 * 24 * 60 * 60; // 30 days
/// Rough number of seconds in a year
const YEAR_SECS: u64 = 365 * 24 * 60 * 60; // 365 days

/// One row of [`UNITS`]: `(magnitude, seconds, unit, singular, plural)`.
type UnitRow = (&'static str, u64, Unit, &'static str, &'static str);

/// Time units in descending order. Drives parsing of the magnitude suffix, the breakdown into
/// [`Expiration::components`] and the human-readable formatting.
const UNITS: [UnitRow; 7] = [
    ("y", YEAR_SECS, Unit::Year, "year", "years"),
    ("M", MONTH_SECS, Unit::Month, "month", "months"),
    ("w", 7 * 24 * 60 * 60, Unit::Week, "week", "weeks"),
    ("d", 24 * 60 * 60, Unit::Day, "day", "days"),
    ("h", 60 * 60, Unit::Hour, "hour", "hours"),
    ("m", 60, Unit::Minute, "min", "mins"),
    ("s", 1, Unit::Second, "sec", "secs"),
];

/// A single [`Expiration`] can either be an unsigned number or an unsigned number followed by `=d`
/// to denote a default expiration.
impl FromStr for Expiration {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (secs, modifier) = match s.split_once('=') {
            Some((secs, modifier)) => (secs, Some(modifier)),
            None => (s, None),
        };

        let secs = if let Some(mag_pos) = secs.find(|c: char| !char::is_ascii_digit(&c)) {
            let (val, mag) = secs.split_at(mag_pos);

            let val = val.parse::<u64>().map_err(Error::ParsingNumber)?;

            let (_, mag, ..) = UNITS
                .iter()
                .find(|(magnitude, ..)| *magnitude == mag)
                .ok_or(Error::IllegalMagnitude)?;

            val.checked_mul(*mag).ok_or(Error::Overflow)?
        } else {
            secs.parse::<u64>().map_err(Error::ParsingNumber)?
        };

        let default = match modifier {
            None => false,
            Some("d") => true,
            Some(_) => return Err(Error::IllegalModifier),
        };

        Ok(Self {
            duration: Duration::from_secs(secs),
            default,
        })
    }
}

/// Print human-readable duration in a very rough approximation.
///
/// Localized renderings live in the server's i18n layer; this English form is the fallback used
/// outside of the web UI.
impl Display for Expiration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const SEPARATOR: &str = ", ";

        if self.duration.is_zero() {
            return f.write_str("never");
        }

        let mut sep = "";

        for (value, (.., singular, plural)) in self.breakdown() {
            let name = if value > 1 { plural } else { singular };
            write!(f, "{sep}{value} {name}")?;
            sep = SEPARATOR;
        }

        Ok(())
    }
}

impl FromStr for ExpirationSet {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut values: Vec<Expiration> = s
            .split(',')
            .map(FromStr::from_str)
            .collect::<Result<_, _>>()?;

        if values.iter().filter(|exp| exp.default).count() > 1 {
            return Err(Error::MultipleDefaults);
        }

        values.sort();

        if values.windows(2).any(|w| w[0].duration == w[1].duration) {
            Err(Error::DuplicateExpirations)?;
        }

        Ok(ExpirationSet(values))
    }
}

impl ExpirationSet {
    /// Retrieve sorted vector of [`Expiration`] values.
    #[must_use]
    pub fn into_inner(self) -> Vec<Expiration> {
        self.0
    }

    /// Borrow the sorted values without consuming the set.
    #[must_use]
    pub fn values(&self) -> &[Expiration] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Expiration {
        fn from_secs(secs: u64) -> Self {
            Self {
                duration: Duration::from_secs(secs),
                default: false,
            }
        }
    }

    #[test]
    fn non_default_expiration() {
        let expiration = "60".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_mins(1));
        assert!(!expiration.default);
    }

    #[test]
    fn expiration_with_magnitude() {
        let expiration = "60s".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_mins(1));

        let expiration = "59m".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_mins(59));

        let expiration = "13h".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_hours(13));

        let expiration = "4d".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_hours(96));

        let expiration = "40w".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_hours(6720));

        let expiration = "12M".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_secs(12 * MONTH_SECS));

        let expiration = "80y".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_secs(80 * YEAR_SECS));

        let expiration = "0y".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_secs(0));
    }

    #[test]
    fn expiration_with_illegal_magnitude() {
        assert!(matches!(
            "1x".parse::<ExpirationSet>(),
            Err(Error::IllegalMagnitude)
        ));
        assert!(matches!(
            "1W".parse::<ExpirationSet>(),
            Err(Error::IllegalMagnitude)
        ));
        assert!(matches!(
            "1dd".parse::<ExpirationSet>(),
            Err(Error::IllegalMagnitude)
        ));
        assert!(matches!(
            "1dh".parse::<ExpirationSet>(),
            Err(Error::IllegalMagnitude)
        ));
        assert!(matches!(
            "1d ".parse::<ExpirationSet>(),
            Err(Error::IllegalMagnitude)
        ));
        assert!(matches!(
            "1d0".parse::<ExpirationSet>(),
            Err(Error::IllegalMagnitude)
        ));
        assert!(matches!(
            "d".parse::<ExpirationSet>(),
            Err(Error::ParsingNumber(_))
        ));
        assert!(matches!(
            "d0".parse::<ExpirationSet>(),
            Err(Error::ParsingNumber(_))
        ));
        assert!(matches!(
            "999999999999y".parse::<ExpirationSet>(),
            Err(Error::Overflow)
        ));
    }

    #[test]
    fn default_expiration() {
        let expiration = "60=d".parse::<Expiration>().unwrap();
        assert_eq!(expiration.duration, Duration::from_mins(1));
        assert!(expiration.default);
    }

    #[test]
    fn illegal_modifier() {
        assert!(matches!(
            "60==d".parse::<ExpirationSet>(),
            Err(Error::IllegalModifier)
        ));

        assert!(matches!(
            "60= d".parse::<ExpirationSet>(),
            Err(Error::IllegalModifier)
        ));

        assert!(matches!(
            "60=e".parse::<ExpirationSet>(),
            Err(Error::IllegalModifier)
        ));

        assert!(matches!(
            "60=d=".parse::<ExpirationSet>(),
            Err(Error::IllegalModifier)
        ));

        assert!(matches!(
            "60=d=d".parse::<ExpirationSet>(),
            Err(Error::IllegalModifier)
        ));

        assert!(matches!(
            "60==".parse::<ExpirationSet>(),
            Err(Error::IllegalModifier)
        ));
    }

    #[test]
    fn expiration_set() {
        let expirations = "3600,60=d,48000"
            .parse::<ExpirationSet>()
            .unwrap()
            .into_inner();

        assert_eq!(expirations.len(), 3);

        assert_eq!(expirations[0].duration, Duration::from_mins(1));
        assert_eq!(expirations[1].duration, Duration::from_hours(1));
        assert_eq!(expirations[2].duration, Duration::from_mins(800));

        assert!(expirations[0].default);
        assert!(!expirations[1].default);
        assert!(!expirations[2].default);

        let expirations2 = "1h,1m=d,800m"
            .parse::<ExpirationSet>()
            .unwrap()
            .into_inner();

        assert_eq!(expirations, expirations2);
    }

    #[test]
    fn multiple_defaults() {
        assert!(matches!(
            "3600=d,60=d,48000".parse::<ExpirationSet>(),
            Err(Error::MultipleDefaults)
        ));
    }

    #[test]
    fn duplicate_expirations() {
        assert!(matches!(
            "60,60=d".parse::<ExpirationSet>(),
            Err(Error::DuplicateExpirations)
        ));
        assert!(matches!(
            "3600,60,48000,60=d,3600".parse::<ExpirationSet>(),
            Err(Error::DuplicateExpirations)
        ));
    }

    #[test]
    fn formatting() {
        assert_eq!(format!("{}", Expiration::from_secs(30)), "30 secs");
        assert_eq!(format!("{}", Expiration::from_secs(60)), "1 min");
        assert_eq!(format!("{}", Expiration::from_secs(60 * 2)), "2 mins");
        assert_eq!(format!("{}", Expiration::from_secs(60 * 60)), "1 hour");
        assert_eq!(format!("{}", Expiration::from_secs(60 * 60 * 2)), "2 hours");
        assert_eq!(format!("{}", Expiration::from_secs(60 * 60 * 24)), "1 day");
        assert_eq!(
            format!("{}", Expiration::from_secs(60 * 60 * 24 * 2)),
            "2 days"
        );
        assert_eq!(
            format!("{}", Expiration::from_secs(60 * 60 * 24 * 7)),
            "1 week"
        );
        assert_eq!(
            format!("{}", Expiration::from_secs(60 * 60 * 24 * 7 * 2)),
            "2 weeks"
        );
        assert_eq!(
            format!("{}", Expiration::from_secs(60 * 60 * 24 * 7 * 4)),
            "4 weeks"
        );
        assert_eq!(
            format!("{}", Expiration::from_secs(60 * 60 * 24 * 7 * 8)),
            "1 month, 3 weeks, 5 days"
        );
        assert_eq!(
            format!("{}", Expiration::from_secs(60 * 60 * 24 * 7 * 4 * 12)),
            "11 months, 6 days"
        );
        assert_eq!(
            format!("{}", Expiration::from_secs(60 * 60 * 24 * 7 * 4 * 24)),
            "1 year, 10 months, 1 week"
        );
        assert_eq!(
            format!(
                "{}",
                Expiration::from_secs(
                    60 * 60 * 24 * 7 * 4 * 24
                        + 60 * 60 * 24 * 7 * 8
                        + 60 * 60 * 24 * 7 * 2
                        + 60 * 60 * 24 * 2
                        + 3 * 60 * 60 * 24
                        + 23 * 60 * 60
                        + 59 * 60
                        + 42
                )
            ),
            "2 years, 2 weeks, 3 days, 23 hours, 59 mins, 42 secs"
        );
        assert_eq!(
            format!(
                "{}",
                Expiration::from_secs(60 * 60 * 24 * 7 * 8 + 60 * 60 * 24 * 2 + 23 * 60 * 60 + 42)
            ),
            "1 month, 4 weeks, 23 hours, 42 secs"
        );

        assert_eq!(format!("{}", "1".parse::<Expiration>().unwrap()), "1 sec");

        assert_eq!(
            format!("{}", "30s".parse::<Expiration>().unwrap()),
            "30 secs"
        );
        assert_eq!(
            format!("{}", "59m".parse::<Expiration>().unwrap()),
            "59 mins"
        );
        assert_eq!(
            format!("{}", "3h".parse::<Expiration>().unwrap()),
            "3 hours"
        );
        assert_eq!(format!("{}", "1d".parse::<Expiration>().unwrap()), "1 day");
        assert_eq!(
            format!("{}", "4w".parse::<Expiration>().unwrap()),
            "4 weeks"
        );
        assert_eq!(
            format!("{}", "12M".parse::<Expiration>().unwrap()),
            "12 months"
        );
        assert_eq!(format!("{}", "1y".parse::<Expiration>().unwrap()), "1 year");
        assert_eq!(format!("{}", Expiration::from_secs(0)), "never");
    }

    #[test]
    fn components() {
        assert_eq!(Expiration::from_secs(0).components(), vec![]);

        assert_eq!(
            Expiration::from_secs(60 * 60 * 24 * 7 * 4 * 24).components(),
            vec![(1, Unit::Year), (10, Unit::Month), (1, Unit::Week)]
        );

        assert_eq!(
            Expiration::from_secs(60 * 60 * 24 * 7 * 8 + 60 * 60 * 24 * 2 + 23 * 60 * 60 + 42)
                .components(),
            vec![
                (1, Unit::Month),
                (4, Unit::Week),
                (23, Unit::Hour),
                (42, Unit::Second)
            ]
        );
    }
}
