use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;

use chacha20poly1305::XNonce;
use rusqlite::{Connection, Transaction, params, params_from_iter};
use rusqlite_migration::{HookError, M, Migrations};
use tokio::sync::oneshot;

use crate::crypto::{self, EntrySalt, Password, Salt};
use crate::expiration::Expiration;
use crate::id::Id;
use read::{DatabaseEntry, ListEntry, Metadata};

/// Failures when opening the database, i.e. only at startup and never while serving a request.
#[derive(thiserror::Error, Debug)]
pub enum OpenError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("migrations error: {0}")]
    Migration(#[from] rusqlite_migration::Error),
}

/// Failures of an individual database operation.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Outcomes the caller is expected to act on.
    #[error("entry not found")]
    NotFound,
    #[error("not allowed to delete")]
    Delete,
    #[error("password not given")]
    NoPassword,
    #[error("wrong password")]
    WrongPassword,

    // Everything below means the request failed for reasons the caller cannot resolve.
    #[error("sqlite error: {0}")]
    Sqlite(rusqlite::Error),
    #[error("failed to compress: {0}")]
    Compression(String),
    #[error("join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::Error),
    #[error("database handler is gone")]
    BackendGone,
}

impl From<oneshot::error::RecvError> for Error {
    fn from(_: oneshot::error::RecvError) -> Self {
        Error::BackendGone
    }
}

/// The programmatic database interface. However, database calls are not translated directly to
/// sqlite but moved forward to a [`Handler`] which reads database commands from a queue and
/// processes them. This is done to avoid locking the underlying non-Send database per call which
/// cuts down performance in half on certain systems.
#[derive(Clone)]
pub struct Database {
    /// Sender for database commands.
    sender: kanal::AsyncSender<Command>,
    /// Salt used to derive encryption keys from paste passwords.
    salt: Salt,
}

/// Actual database handler that owns the connection to the underlying sqlite database.
struct Handler {
    conn: Connection,
    /// Receiver for database commands.
    receiver: kanal::Receiver<Command>,
}

/// The metadata columns, in the order [`metadata_from_row`] expects them. Kept in one place so
/// the metadata-only and full-entry queries cannot drift out of sync with the parser.
macro_rules! metadata_columns {
    () => {
        "uid, title, CAST(ROUND((julianday(expires) - julianday('now')) * 86400) AS INTEGER), burn_after_reading, expires < datetime('now'), nonce IS NOT NULL"
    };
}

/// Hand `value` back to the caller that issued the command.
///
/// A caller that went away before its response arrived — a disconnected client or a request that
/// hit the timeout — is not a reason to tear down the handler, so the value is simply dropped.
fn reply<T>(result: oneshot::Sender<T>, value: T) {
    if result.send(value).is_err() {
        tracing::debug!("caller went away before receiving its database response");
    }
}

/// Parse the leading metadata columns of a row into [`Metadata`] plus whether the entry expired.
fn metadata_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Metadata, bool)> {
    let expiration = row
        .get::<_, Option<i64>>(2)?
        .filter(|secs| *secs > 0)
        .and_then(|secs| u64::try_from(secs).ok())
        .map(|secs| Expiration {
            duration: Duration::from_secs(secs),
        });

    Ok((
        read::Metadata {
            uid: row.get(0)?,
            title: row.get::<_, Option<String>>(1)?,
            expiration,
            must_be_deleted: row.get::<_, Option<bool>>(3)?.unwrap_or(false),
            is_encrypted: row.get::<_, Option<bool>>(5)?.unwrap_or(false),
        },
        row.get::<_, Option<bool>>(4)?.unwrap_or(false),
    ))
}

/// Commands issued to the database handler and corresponding to [`Database`] calls.
enum Command {
    Insert {
        entry: write::DatabaseEntry,
        result: oneshot::Sender<Result<(Id, write::Entry), Error>>,
    },
    Get {
        id: Id,
        result: oneshot::Sender<Result<DatabaseEntry, Error>>,
    },
    GetMetadata {
        id: Id,
        result: oneshot::Sender<Result<(Metadata, bool), Error>>,
    },
    Delete {
        id: Id,
        result: oneshot::Sender<Result<(), Error>>,
    },
    Take {
        id: Id,
        result: oneshot::Sender<Result<bool, Error>>,
    },
    DeleteMany {
        ids: Vec<Id>,
        result: oneshot::Sender<Result<usize, Error>>,
    },
    DeleteFor {
        id: Id,
        uids: Vec<i64>,
        result: oneshot::Sender<Result<(), Error>>,
    },
    NextUid {
        result: oneshot::Sender<Result<i64, Error>>,
    },
    List {
        result: oneshot::Sender<Result<Vec<ListEntry>, Error>>,
    },
    Purge {
        result: oneshot::Sender<Result<Vec<Id>, Error>>,
    },
    Ping {
        result: oneshot::Sender<Result<(), Error>>,
    },
}

/// Database opening modes
#[derive(Debug)]
pub enum Open {
    /// Open in-memory database that is wiped after reload
    Memory,
    /// Open database from given path
    Path(PathBuf),
}

/// Module with types for insertion.
pub mod write {
    use crate::crypto::{Derivation, Encrypted, EntrySalt, Password, Plaintext};
    use crate::db::Error;
    use chacha20poly1305::XNonce;
    use std::io::Cursor;
    use std::num::NonZeroU32;
    use tokio::task::spawn_blocking;

    /// An uncompressed entry to be inserted into the database.
    #[derive(Default, Debug)]
    pub struct Entry {
        /// Content
        pub text: String,
        /// File extension
        pub extension: Option<String>,
        /// Expiration in seconds from now
        pub expires: Option<NonZeroU32>,
        /// Delete if read
        pub burn_after_reading: Option<bool>,
        /// User identifier that inserted the entry
        pub uid: Option<i64>,
        /// Optional password to encrypt the entry
        pub password: Option<String>,
        /// Title
        pub title: Option<String>,
    }

    /// A compressed entry to be inserted.
    pub struct CompressedEntry {
        /// Original data
        entry: Entry,
        /// Compressed data
        data: Vec<u8>,
    }

    /// An entry that might be encrypted.
    pub struct DatabaseEntry {
        /// Original data
        pub entry: Entry,
        /// Compressed and potentially encrypted data
        pub data: Vec<u8>,
        /// Nonce for this entry
        pub nonce: Option<XNonce>,
        /// Salt this entry's key was derived under, if it is encrypted
        pub salt: Option<EntrySalt>,
    }

    impl Entry {
        /// Compress the entry for insertion.
        ///
        /// The data is in memory, so there is nothing to await: compression is pure CPU work and
        /// runs on a blocking thread rather than stalling an executor thread for the whole body.
        pub async fn compress(self) -> Result<CompressedEntry, Error> {
            spawn_blocking(move || {
                let data = zstd::stream::encode_all(
                    Cursor::new(self.text.as_bytes()),
                    zstd::DEFAULT_COMPRESSION_LEVEL,
                )
                .map_err(|e| Error::Compression(e.to_string()))?;

                Ok(CompressedEntry { entry: self, data })
            })
            .await?
        }
    }

    impl CompressedEntry {
        /// Encrypt if password is set, under a salt minted for this entry alone.
        pub async fn encrypt(self) -> Result<DatabaseEntry, Error> {
            let (data, nonce, salt) = if let Some(password) = &self.entry.password {
                let password = Password::from(password.as_bytes().to_vec());
                let plaintext = Plaintext::from(self.data);
                let salt = EntrySalt::generate();
                let Encrypted { ciphertext, nonce } = plaintext
                    .encrypt(password, Derivation::PerEntry(salt.clone()))
                    .await?;
                (ciphertext, Some(nonce), Some(salt))
            } else {
                (self.data, None, None)
            };

            Ok(DatabaseEntry {
                entry: self.entry,
                data,
                nonce,
                salt,
            })
        }
    }
}

/// Module with types for reading from the database.
pub mod read {
    use crate::crypto::{Derivation, Encrypted, EntrySalt, Password, Salt};
    use crate::db::Error;
    use crate::expiration::Expiration;
    use crate::id::Id;
    use chacha20poly1305::XNonce;
    use std::io::Cursor;
    use tokio::task::spawn_blocking;

    /// A raw entry as read from the database.
    #[derive(Debug)]
    pub struct DatabaseEntry {
        /// Compressed and potentially encrypted data
        pub data: Vec<u8>,
        /// Metadata
        pub metadata: Metadata,
        /// Entry is expired
        pub expired: bool,
        /// Nonce for this entry
        pub nonce: Option<XNonce>,
        /// Salt this entry was sealed under. `None` for entries stored before each carried one,
        /// which are still opened with the process-wide salt they were sealed with.
        pub salt: Option<EntrySalt>,
    }

    /// Potentially decrypted but still compressed entry
    #[derive(Debug)]
    pub struct CompressedReadEntry {
        /// Compressed data
        data: Vec<u8>,
        /// Metadata
        metadata: Metadata,
    }

    /// Uncompressed, decrypted data read from the database.
    #[derive(Debug)]
    pub struct Data {
        /// Content
        pub text: String,
        /// Metadata
        pub metadata: Metadata,
    }

    /// Paste metadata, i.e. anything but actual content.
    #[derive(Debug)]
    pub struct Metadata {
        /// User identifier that inserted the entry
        pub uid: Option<i64>,
        /// Title
        pub title: Option<String>,
        /// Entry expiration datetime
        pub expiration: Option<Expiration>,
        /// Entry will be deleted the next time it is fetched via [`Database::get`].
        pub must_be_deleted: bool,
        /// Entry's content is encrypted, so reading it needs a password.
        ///
        /// The title is not encrypted along with it, so a view that shows one before the password
        /// is supplied has to consult this.
        pub is_encrypted: bool,
    }

    /// Potentially deleted or non-existent expired entry.
    #[derive(Debug)]
    pub enum Entry {
        /// Entry found and still available.
        Regular(Data),
        /// Entry burned.
        Burned(Data),
    }

    /// A simple entry as read from the database for listing purposes.
    #[derive(Debug)]
    pub struct ListEntry {
        /// Identifier
        pub id: Id,
        /// Optional title
        pub title: Option<String>,
        /// If entry is encrypted
        pub is_encrypted: bool,
        /// If entry is deleted once it has been read
        pub is_burn_after_reading: bool,
        /// Expiration if set
        pub expiration: Option<String>,
        /// If entry is expired
        pub is_expired: bool,
    }

    impl DatabaseEntry {
        /// Decrypt with the derivation this entry was sealed under.
        ///
        /// `legacy_salt` is the process-wide salt, used only for entries stored before each
        /// carried its own; those are already in databases and cannot be re-keyed in place.
        pub async fn decrypt(
            self,
            password: Option<Password>,
            legacy_salt: &Salt,
        ) -> Result<CompressedReadEntry, Error> {
            let derivation = match self.salt {
                Some(salt) => Derivation::PerEntry(salt),
                None => Derivation::Legacy(legacy_salt.clone()),
            };

            match (self.nonce, password) {
                (Some(_), None) => Err(Error::NoPassword),
                (None, None | Some(_)) => Ok(CompressedReadEntry {
                    data: self.data,
                    metadata: self.metadata,
                }),
                (Some(nonce), Some(password)) => {
                    let encrypted = Encrypted::new(self.data, nonce);
                    // A failing AEAD check means the supplied password was wrong; surface that as
                    // an outcome rather than leaking a cipher primitive failure to callers.
                    let decrypted =
                        encrypted
                            .decrypt(password, derivation)
                            .await
                            .map_err(|err| match err {
                                crate::crypto::Error::ChaCha20Poly1305Decrypt => {
                                    Error::WrongPassword
                                }
                                err => Error::Crypto(err),
                            })?;
                    Ok(CompressedReadEntry {
                        data: decrypted,
                        metadata: self.metadata,
                    })
                }
            }
        }
    }

    impl CompressedReadEntry {
        /// Decompress on a blocking thread, see [`super::write::Entry::compress`].
        pub async fn decompress(self) -> Result<Data, Error> {
            spawn_blocking(move || {
                let data = zstd::stream::decode_all(Cursor::new(self.data))
                    .map_err(|e| Error::Compression(e.to_string()))?;

                let text =
                    String::from_utf8(data).map_err(|e| Error::Compression(e.to_string()))?;

                Ok(Data {
                    text,
                    metadata: self.metadata,
                })
            })
            .await?
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        if let rusqlite::Error::QueryReturnedNoRows = err {
            Error::NotFound
        } else {
            tracing::warn!("Unhandled rusqlite error type: {err:?}");
            Error::Sqlite(err)
        }
    }
}

impl Handler {
    /// Create new database with the given `method`.
    fn new(method: Open, receiver: kanal::Receiver<Command>) -> Result<Self, OpenError> {
        tracing::debug!("opening {method:?}");

        let mut conn = match method {
            Open::Memory => Connection::open_in_memory()?,
            Open::Path(path) => {
                // sqlite creates the file 0644, so on a shared host every local account could read
                // every unencrypted paste on the instance. Only a file this process just created
                // is tightened; an existing one keeps whatever the operator chose for it.
                let is_new = !path.exists();
                let conn = Connection::open(&path)?;

                #[cfg(unix)]
                if is_new {
                    use std::os::unix::fs::PermissionsExt;

                    if let Err(err) =
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    {
                        tracing::warn!("could not restrict database file permissions: {err}");
                    }
                }

                #[cfg(not(unix))]
                let _ = is_new;

                conn
            }
        };

        // Burn-after-reading promises the content is gone once read, but sqlite only unlinks the
        // page: the plaintext otherwise stays in the freelist until something reuses it, and comes
        // back out of the file, a backup or a snapshot long after the paste "burned".
        conn.pragma_update(None, "secure_delete", "ON")?;

        let migrations = Migrations::new(vec![
            M::up(include_str!("migrations/0001-initial.sql")),
            M::up(include_str!("migrations/0002-add-created-column.sql")),
            M::up(include_str!(
                "migrations/0003-drop-created-add-uid-column.sql"
            )),
            M::up_with_hook(
                include_str!("migrations/0004-add-compressed-column.sql"),
                |tx: &Transaction| {
                    let mut stmt = tx.prepare("SELECT id, text FROM entries")?;

                    let rows = stmt
                        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                        .collect::<Result<Vec<(u32, String)>, _>>()?;

                    tracing::debug!("compressing {} rows", rows.len());

                    for (id, text) in rows {
                        let cursor = Cursor::new(text);
                        let data =
                            zstd::stream::encode_all(cursor, zstd::DEFAULT_COMPRESSION_LEVEL)
                                .map_err(|e| HookError::Hook(e.to_string()))?;

                        tx.execute(
                            "UPDATE entries SET data = ?1 WHERE id = ?2",
                            params![data, id],
                        )?;
                    }

                    Ok(())
                },
            ),
            M::up(include_str!("migrations/0005-drop-text-column.sql")),
            M::up(include_str!("migrations/0006-add-nonce-column.sql")),
            M::up(include_str!("migrations/0007-add-title-column.sql")),
            M::up(include_str!("migrations/0008-add-salt-column.sql")),
        ]);

        migrations.to_latest(&mut conn)?;

        Ok(Self { conn, receiver })
    }

    /// Run database command loop.
    fn run(mut self) {
        loop {
            let command = match self.receiver.recv() {
                Ok(command) => command,
                // sender closed, application is shutting down..
                Err(kanal::ReceiveError::Closed | kanal::ReceiveError::SendClosed) => return,
            };

            match command {
                Command::Insert { entry, result } => reply(result, self.insert(entry)),
                Command::Get { id, result } => reply(result, self.get(id)),
                Command::GetMetadata { id, result } => reply(result, self.get_metadata(id)),
                Command::Delete { id, result } => reply(result, self.delete(id)),
                Command::Take { id, result } => reply(result, self.take(id)),
                Command::DeleteMany { ids, result } => reply(result, self.delete_many(ids)),
                Command::DeleteFor { id, uids, result } => {
                    reply(result, self.delete_for(id, &uids));
                }
                Command::NextUid { result } => reply(result, self.next_uid()),
                Command::List { result } => reply(result, self.list()),
                Command::Purge { result } => reply(result, self.purge()),
                Command::Ping { result } => reply(result, self.ping()),
            }
        }
    }

    fn insert(
        &self,
        write::DatabaseEntry {
            entry,
            data,
            nonce,
            salt,
        }: write::DatabaseEntry,
    ) -> Result<(Id, write::Entry), Error> {
        let mut counter = 0;
        let nonce = nonce.as_ref().map(|n| n.as_slice());
        let salt = salt.as_ref().map(EntrySalt::as_bytes);
        // `datetime('now', NULL)` yields NULL, i.e. no expiration.
        let expires = entry.expires.map(|expires| format!("{expires} seconds"));

        loop {
            let id = Id::rand();

            let result = self.conn.execute(
                "INSERT INTO entries (id, uid, data, burn_after_reading, nonce, expires, title, salt) VALUES (?1, ?2, ?3, ?4, ?5, datetime('now', ?6), ?7, ?8)",
                params![
                    id.to_i64(),
                    entry.uid,
                    data,
                    entry.burn_after_reading,
                    nonce,
                    expires,
                    entry.title,
                    salt,
                ],
            );

            match result {
                Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code,
                        extended_code,
                    },
                    Some(ref _message),
                )) if code == rusqlite::ErrorCode::ConstraintViolation
                    && extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                    && counter < 10 =>
                {
                    // Retry if ID is already existent
                    counter += 1;
                    continue;
                }
                Err(err) => break Err(err)?,
                Ok(rows) => {
                    debug_assert_eq!(rows, 1);
                    return Ok((id, entry));
                }
            }
        }
    }

    /// Read a row's metadata along with whether it has already expired.
    fn get_metadata(&self, id: Id) -> Result<(Metadata, bool), Error> {
        let metadata = self.conn.query_row(
            concat!("SELECT ", metadata_columns!(), " FROM entries WHERE id=?1"),
            params![id.to_i64()],
            metadata_from_row,
        )?;

        Ok(metadata)
    }

    fn get(&self, id: Id) -> Result<DatabaseEntry, Error> {
        let entry = self.conn.query_row(
            concat!(
                "SELECT ",
                metadata_columns!(),
                ", data, nonce, salt FROM entries WHERE id=?1"
            ),
            params![id.to_i64()],
            |row| {
                let (metadata, expired) = metadata_from_row(row)?;

                let nonce = row
                    .get::<_, Option<Vec<_>>>(7)?
                    .map(|v| XNonce::try_from(v.as_slice()))
                    .transpose()
                    .map_err(|err| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Blob,
                            Box::new(err),
                        )
                    })?;

                let salt = row
                    .get::<_, Option<Vec<u8>>>(8)?
                    .map(EntrySalt::try_from)
                    .transpose()
                    .map_err(|err| {
                        rusqlite::Error::FromSqlConversionFailure(
                            8,
                            rusqlite::types::Type::Blob,
                            Box::new(err),
                        )
                    })?;

                Ok(read::DatabaseEntry {
                    data: row.get(6)?,
                    metadata,
                    nonce,
                    expired,
                    salt,
                })
            },
        )?;

        Ok(entry)
    }

    fn delete(&self, id: Id) -> Result<(), Error> {
        self.conn
            .execute("DELETE FROM entries WHERE id=?1", params![id.to_i64()])?;

        Ok(())
    }

    /// Delete `id`, reporting whether this call is the one that removed the row.
    ///
    /// Commands run one at a time, so for concurrent readers of the same burn-after-reading
    /// entry exactly one `DELETE` reports an affected row.
    fn take(&self, id: Id) -> Result<bool, Error> {
        let affected = self
            .conn
            .execute("DELETE FROM entries WHERE id=?1", params![id.to_i64()])?;

        Ok(affected > 0)
    }

    fn delete_many(&mut self, ids: Vec<Id>) -> Result<usize, Error> {
        let tx = self.conn.transaction()?;

        let mut affected = 0;

        for id in ids {
            affected += tx.execute("DELETE FROM entries WHERE id=?1", params![id.to_i64()])?;
        }

        tx.commit()?;
        Ok(affected)
    }

    fn delete_for(&self, id: Id, uids: &[i64]) -> Result<(), Error> {
        if uids.is_empty() {
            return Err(Error::Delete);
        }

        let placeholders = vec!["?"; uids.len()].join(",");
        let delete_sql = format!("DELETE FROM entries WHERE id=? AND uid IN ({placeholders})");

        let params = std::iter::once(id.to_i64()).chain(uids.iter().copied());
        let affected = self.conn.execute(&delete_sql, params_from_iter(params))?;

        if affected == 0 {
            return Err(Error::Delete);
        }

        Ok(())
    }

    fn next_uid(&self) -> Result<i64, Error> {
        let uid = self.conn.query_row(
            "UPDATE uids SET n = n + 1 WHERE id = 0 RETURNING n",
            [],
            |row| row.get(0),
        )?;

        Ok(uid)
    }

    fn ping(&self) -> Result<(), Error> {
        self.conn.query_row("SELECT 1", [], |_| Ok(()))?;

        Ok(())
    }

    fn list(&self) -> Result<Vec<ListEntry>, Error> {
        let entries = self
            .conn
            .prepare(
                "SELECT id, title, nonce, burn_after_reading, expires, expires < datetime('now') FROM entries",
            )?
            .query_map([], |row| {
                Ok(ListEntry {
                    id: Id::from(row.get::<_, i64>(0)?),
                    title: row.get(1)?,
                    is_encrypted: row.get::<_, Option<Vec<u8>>>(2)?.is_some(),
                    is_burn_after_reading: row.get::<_, Option<bool>>(3)?.unwrap_or_default(),
                    expiration: row.get(4)?,
                    is_expired: row.get::<_, Option<bool>>(5)?.unwrap_or_default(),
                })
            })?
            .collect::<Result<_, _>>()?;

        Ok(entries)
    }

    fn purge(&self) -> Result<Vec<Id>, Error> {
        let ids = self
            .conn
            .prepare("DELETE FROM entries WHERE expires < datetime('now') RETURNING id")?
            .query_map([], |row| Ok(Id::from(row.get::<_, i64>(0)?)))?
            .collect::<Result<_, _>>()?;

        Ok(ids)
    }
}

impl Database {
    /// Create new database with the given `method` as well as a [`Handler`] future that makes the
    /// actual calls.
    pub fn new(
        method: Open,
        salt: Salt,
    ) -> Result<
        (
            Self,
            impl Future<Output = Result<(), tokio::task::JoinError>>,
        ),
        OpenError,
    > {
        let (sender, receiver) = kanal::bounded(256);
        let sender = sender.to_async();
        let handler = Handler::new(method, receiver)?;
        let fut = async move { tokio::task::spawn_blocking(|| handler.run()).await };
        Ok((Self { sender, salt }, fut))
    }

    /// Send `command` to the [`Handler`] and await its response.
    async fn call<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T, Error>>) -> Command,
    ) -> Result<T, Error> {
        let (result, command_result) = oneshot::channel();
        self.sender
            .send(command(result))
            .await
            .map_err(|_| Error::BackendGone)?;

        command_result.await?
    }

    /// Insert `entry` under a new random id into the database and optionally set owner to `uid`.
    /// Returns the id of the new entry on success.
    pub async fn insert(&self, entry: write::Entry) -> Result<(Id, write::Entry), Error> {
        let entry = entry.compress().await?.encrypt().await?;

        self.call(|result| Command::Insert { entry, result }).await
    }

    /// Get entire entry for `id`.
    pub async fn get(&self, id: Id, password: Option<Password>) -> Result<read::Entry, Error> {
        let entry = self.call(|result| Command::Get { id, result }).await?;

        if entry.expired {
            self.delete(id).await?;
            return Err(Error::NotFound);
        }

        let data = entry
            .decrypt(password, &self.salt)
            .await?
            .decompress()
            .await?;

        if data.metadata.must_be_deleted {
            // The delete is what settles the race: readers that arrive together all decrypt
            // successfully, but only the one that actually removed the row may see the content.
            // Deleting after decryption keeps a wrong password from burning the entry.
            if !self.take(id).await? {
                return Err(Error::NotFound);
            }

            return Ok(read::Entry::Burned(data));
        }

        Ok(read::Entry::Regular(data))
    }

    /// Get metadata of a paste.
    ///
    /// Expired entries are deleted and reported as [`Error::NotFound`], matching [`Self::get`],
    /// so callers can rely on metadata alone to decide a paste is still servable.
    pub async fn get_metadata(&self, id: Id) -> Result<Metadata, Error> {
        let (metadata, expired) = self
            .call(|result| Command::GetMetadata { id, result })
            .await?;

        if expired {
            self.delete(id).await?;
            return Err(Error::NotFound);
        }

        Ok(metadata)
    }

    /// Delete paste with `id`.
    async fn delete(&self, id: Id) -> Result<(), Error> {
        self.call(|result| Command::Delete { id, result }).await
    }

    /// Delete paste with `id`, reporting whether this call removed it.
    async fn take(&self, id: Id) -> Result<bool, Error> {
        self.call(|result| Command::Take { id, result }).await
    }

    /// Delete pastes with `ids`.
    pub async fn delete_many(&self, ids: Vec<Id>) -> Result<usize, Error> {
        self.call(|result| Command::DeleteMany { ids, result })
            .await
    }

    /// Delete paste with `id` if any of `uids` owns it.
    pub async fn delete_for(&self, id: Id, uids: &[i64]) -> Result<(), Error> {
        self.call(|result| Command::DeleteFor {
            id,
            uids: uids.to_vec(),
            result,
        })
        .await
    }

    /// Retrieve next monotonically increasing uid.
    pub async fn next_uid(&self) -> Result<i64, Error> {
        self.call(|result| Command::NextUid { result }).await
    }

    /// List all entries.
    pub async fn list(&self) -> Result<Vec<ListEntry>, Error> {
        self.call(|result| Command::List { result }).await
    }

    /// Purge all expired entries and return their [`Id`]s
    pub async fn purge(&self) -> Result<Vec<Id>, Error> {
        self.call(|result| Command::Purge { result }).await
    }

    /// Round-trip a trivial query through the handler.
    ///
    /// Proves the channel is open, the actor loop is consuming commands, and the connection still
    /// answers — the three things a dead actor takes down together.
    pub async fn ping(&self) -> Result<(), Error> {
        self.call(|result| Command::Ping { result }).await
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    impl read::Entry {
        /// Unwrap inner data or panic.
        #[must_use]
        pub fn unwrap_inner(self) -> read::Data {
            match self {
                read::Entry::Regular(data) | read::Entry::Burned(data) => data,
            }
        }
    }

    /// Build a scratch path for a file-backed database, unique per test.
    fn scratch_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("wastebin-test-{}-{name}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// Burn-after-reading promises the content is gone once read, but sqlite only unlinks the
    /// page: without `secure_delete` the plaintext stayed in the freelist, recoverable from the
    /// file, a backup or a snapshot long after the paste "burned".
    #[tokio::test]
    async fn a_burned_entry_leaves_nothing_behind() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch_path("burned");
        let marker = "qZx7Z-BURN-MARKER-nP2wK-not-compressible-2f8a1c";

        {
            let (db, handler) = Database::new(
                Open::Path(path.clone()),
                Salt::try_from("testsalt".to_string())?,
            )?;
            let task = tokio::spawn(handler);

            let entry = write::Entry {
                text: marker.to_string(),
                burn_after_reading: Some(true),
                ..Default::default()
            };
            let (id, _) = db.insert(entry).await?;

            // Reading it burns it.
            db.get(id, None).await?;
            assert!(matches!(db.get(id, None).await, Err(Error::NotFound)));

            drop(db);
            let _ = task.await;
        }

        let bytes = std::fs::read(&path)?;
        let found = bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes());

        let _ = std::fs::remove_file(&path);
        assert!(!found, "burned plaintext is still in the database file");

        Ok(())
    }

    /// The file holds every unencrypted paste on the instance. sqlite creates it 0644, so on a
    /// shared host every local account could read the lot.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_new_database_file_is_not_readable_by_others()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let path = scratch_path("perms");
        let (db, handler) = Database::new(
            Open::Path(path.clone()),
            Salt::try_from("testsalt".to_string())?,
        )?;
        let task = tokio::spawn(handler);
        db.ping().await?;

        let mode = std::fs::metadata(&path)?.permissions().mode();

        drop(db);
        let _ = task.await;
        let _ = std::fs::remove_file(&path);

        assert_eq!(mode & 0o077, 0, "mode is {:o}", mode & 0o777);

        Ok(())
    }

    fn new_db() -> Result<Database, Box<dyn std::error::Error>> {
        let (db, handler) = Database::new(Open::Memory, Salt::try_from("testsalt".to_string())?)?;
        tokio::spawn(handler);
        Ok(db)
    }

    /// Listing is the only view an operator has of the database, and a paste that disappears on
    /// first read used to look exactly like one that stays.
    #[tokio::test]
    async fn list_reports_burn_after_reading() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        db.insert(write::Entry {
            text: "stays".to_string(),
            ..Default::default()
        })
        .await?;
        db.insert(write::Entry {
            text: "burns".to_string(),
            burn_after_reading: Some(true),
            ..Default::default()
        })
        .await?;

        let entries = db.list().await?;
        assert_eq!(entries.len(), 2);

        let burning = entries
            .iter()
            .filter(|entry| entry.is_burn_after_reading)
            .count();
        assert_eq!(burning, 1);

        Ok(())
    }

    #[tokio::test]
    async fn insert() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let entry = write::Entry {
            text: "hello world".to_string(),
            uid: Some(10),
            ..Default::default()
        };

        let (id, _entry) = db.insert(entry).await?;

        let entry = db.get(id, None).await?.unwrap_inner();
        assert_eq!(entry.text, "hello world");
        assert!(entry.metadata.uid.is_some());
        assert_eq!(entry.metadata.uid.unwrap(), 10);

        let result = db.get(Id::from(5678u32), None).await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn concurrent_reads_burn_an_entry_exactly_once() -> Result<(), Box<dyn std::error::Error>>
    {
        for _ in 0..32 {
            let db = new_db()?;

            let (id, _entry) = db
                .insert(write::Entry {
                    text: "burn me".to_string(),
                    burn_after_reading: Some(true),
                    ..Default::default()
                })
                .await?;

            let readers = (0..16)
                .map(|_| {
                    let db = db.clone();
                    tokio::spawn(async move { db.get(id, None).await })
                })
                .collect::<Vec<_>>();

            let mut served = 0;
            for reader in readers {
                if let Ok(read::Entry::Burned(data)) = reader.await? {
                    assert_eq!(data.text, "burn me");
                    served += 1;
                }
            }

            assert_eq!(
                served, 1,
                "burn entry served to {served} concurrent readers"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn next_uid() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let uid1 = db.next_uid().await?;
        let uid2 = db.next_uid().await?;
        let uid3 = db.next_uid().await?;

        assert!(uid1 < uid2);
        assert!(uid2 < uid3);

        Ok(())
    }

    #[tokio::test]
    async fn ping_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        assert!(db.ping().await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn caller_going_away_keeps_handler_alive() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        // Enqueue a command whose caller is already gone, so the handler cannot deliver the
        // response.
        let (result, command_result) = oneshot::channel();
        drop(command_result);
        db.sender
            .send(Command::NextUid { result })
            .await
            .map_err(|_| Error::BackendGone)?;

        // The handler must keep serving everyone else.
        assert!(db.next_uid().await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn expired_does_not_exist() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let entry = write::Entry {
            expires: Some(NonZeroU32::new(1).unwrap()),
            ..Default::default()
        };

        let (id, _entry) = db.insert(entry).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let result = db.get(id, None).await;
        assert!(matches!(result, Err(Error::NotFound)));

        Ok(())
    }

    #[tokio::test]
    async fn delete() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let (id, _entry) = db.insert(write::Entry::default()).await?;

        assert!(db.get(id, None).await.is_ok());
        assert!(db.delete(id).await.is_ok());
        assert!(db.get(id, None).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn delete_for() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let uid = 42;

        let entry = write::Entry {
            uid: Some(uid),
            ..Default::default()
        };
        let (id, _entry) = db.insert(entry).await?;

        assert!(db.get(id, None).await.is_ok());
        assert!(db.delete_for(id, &[uid]).await.is_ok());
        assert!(db.get(id, None).await.is_err());

        let entry = write::Entry {
            uid: Some(uid),
            ..Default::default()
        };
        let (id, _entry) = db.insert(entry).await?;

        let incorrect_uid = 99;
        assert!(matches!(
            db.delete_for(id, &[incorrect_uid]).await,
            Err(Error::Delete)
        ));

        // Multi-uid: passes if any uid in the list matches.
        let entry = write::Entry {
            uid: Some(uid),
            ..Default::default()
        };
        let (id, _entry) = db.insert(entry).await?;

        assert!(db.delete_for(id, &[99, uid, 7]).await.is_ok());
        assert!(db.get(id, None).await.is_err());

        // Empty slice: nothing to authorize against.
        let entry = write::Entry {
            uid: Some(uid),
            ..Default::default()
        };
        let (id, _entry) = db.insert(entry).await?;

        assert!(matches!(db.delete_for(id, &[]).await, Err(Error::Delete)));

        assert!(db.get(id, None).await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn purge() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let entry = write::Entry {
            expires: Some(NonZeroU32::new(1).unwrap()),
            ..Default::default()
        };

        let (id, _entry) = db.insert(entry).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let ids = db.purge().await?;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], id);

        Ok(())
    }

    #[tokio::test]
    async fn get_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let entry = write::Entry {
            text: "test content".to_string(),
            uid: Some(42),
            title: Some("Test Title".to_string()),
            expires: Some(NonZeroU32::new(3600).unwrap()),
            ..Default::default()
        };

        let (id, _entry) = db.insert(entry).await?;

        let metadata = db.get_metadata(id).await?;
        assert_eq!(metadata.uid, Some(42));
        assert_eq!(metadata.title, Some("Test Title".to_string()));

        let expiration = metadata.expiration.unwrap().duration.as_secs();
        assert!(expiration <= 3600);
        // We have a problem if the test takes more than 10 seconds.
        assert!(expiration >= 3590);

        Ok(())
    }
}
