use super::Result;
use parking_lot::Mutex;
use redb::{
    BackendError, Database, DatabaseError, ReadableDatabase, ReadableTable, StorageBackend,
    TableDefinition,
};
use std::fs::{File, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::NamedTempFile;

const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("offline_wallet_v1");
const CACHE_BYTES: usize = 2 * 1024 * 1024;

// Older signing processes use a whole-file OS lock. Take the same lock before
// inspecting any bytes and keep it for this backend's entire lifetime. redb
// uses this backend in its default ExclusiveWriter mode only.
#[derive(Debug)]
struct JournalFile(Mutex<File>);

impl JournalFile {
    fn lock(file: File) -> Result<Self> {
        match file.try_lock() {
            Ok(()) => Ok(Self(Mutex::new(file))),
            Err(TryLockError::WouldBlock) => Err(DatabaseError::DatabaseAlreadyOpen.into()),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

impl StorageBackend for JournalFile {
    fn len(&self) -> std::result::Result<u64, BackendError> {
        Ok(self.0.lock().metadata()?.len())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> std::result::Result<(), BackendError> {
        let mut file = self.0.lock();
        file.seek(SeekFrom::Start(offset))?;
        Ok(file.read_exact(out)?)
    }

    fn write(&self, offset: u64, data: &[u8]) -> std::result::Result<(), BackendError> {
        let mut file = self.0.lock();
        file.seek(SeekFrom::Start(offset))?;
        Ok(file.write_all(data)?)
    }

    fn sync_data(&self) -> std::result::Result<(), BackendError> {
        Ok(self.0.lock().sync_data()?)
    }

    fn set_len(&self, len: u64) -> std::result::Result<(), BackendError> {
        Ok(self.0.lock().set_len(len)?)
    }
}

// Both backends hold an exclusive process lock until the command completes.
// Existing sled journals stay authoritative, including their previous signing decisions.
pub(super) enum Journal {
    Legacy(sled::Db),
    Current(Database),
}

impl Journal {
    pub(super) fn open(dir: &Path) -> Result<Self> {
        let path = dir.join("offline-wallet.redb");
        if dir.join("conf").try_exists()? || dir.join("db").try_exists()? {
            if path.try_exists()? || !dir.join("conf").is_file() || !dir.join("db").is_file() {
                return Err("incomplete or ambiguous offline wallet journal".into());
            }
            return Ok(Self::Legacy(
                sled::Config::new()
                    .path(dir)
                    .cache_capacity(CACHE_BYTES as u64)
                    .open()?,
            ));
        }
        let mut directory = std::fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut directory, 0o700);
        directory.create(dir)?;
        let mut builder = Database::builder();
        builder.set_cache_size(CACHE_BYTES);
        if !path.try_exists()? {
            // Publish a fully initialized database. A competing creator can win the
            // filename, in which case both processes must use that creator's ledger.
            let staged = NamedTempFile::new_in(dir)?;
            let db = builder.create_with_backend(JournalFile::lock(staged.reopen()?)?)?;
            let mut tx = db.begin_write()?;
            tx.set_two_phase_commit(true);
            tx.open_table(RECORDS)?;
            tx.commit()?;
            db.close()?;
            staged.as_file().sync_all()?;
            match staged.persist_noclobber(&path) {
                Ok(_) => (),
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error.into()),
            }
            #[cfg(unix)]
            std::fs::File::open(dir)?.sync_all()?;
        }
        let backend = JournalFile::lock(File::options().read(true).write(true).open(path)?)?;
        if backend.len()? == 0 {
            return Err("empty offline wallet journal".into());
        }
        let db = builder
            .set_check_integrity_on_open(true)
            .create_with_backend(backend)?;
        db.begin_read()?.open_table(RECORDS)?;
        Ok(Self::Current(db))
    }

    pub(super) fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Legacy(db) => Ok(db.get(key)?.map(|value| value.to_vec())),
            Self::Current(db) => Ok(db
                .begin_read()?
                .open_table(RECORDS)?
                .get(key)?
                .map(|value| value.value().to_vec())),
        }
    }

    // The database lock covers validation of this pin/decision and the durable write.
    pub(super) fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        match self {
            Self::Legacy(db) => {
                db.insert(key, value)?;
                db.flush()?;
            }
            Self::Current(db) => {
                let mut tx = db.begin_write()?;
                tx.set_two_phase_commit(true);
                tx.open_table(RECORDS)?.insert(key, value)?;
                tx.commit()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_decision_survives_reopen_and_both_writers_exclude_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = Journal::open(dir.path()).unwrap();
        wallet.set(b"request", b"decision").unwrap();
        let path = dir.path().join("offline-wallet.redb");
        let prior = std::fs::File::options()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert!(matches!(
            prior.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(wallet);
        prior.try_lock().unwrap();
        assert!(Journal::open(dir.path()).is_err());
        drop(prior);
        let reopened = Journal::open(dir.path()).unwrap();
        assert_eq!(reopened.get(b"request").unwrap().unwrap(), b"decision");
    }

    #[test]
    fn damaged_or_unrelated_database_cannot_become_a_new_signing_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("offline-wallet.redb");
        std::fs::File::create(&path).unwrap();
        assert!(Journal::open(dir.path()).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);

        let table = TableDefinition::<u64, u64>::new("unrelated");
        let db = Database::create(&path).unwrap();
        let tx = db.begin_write().unwrap();
        tx.open_table(table).unwrap().insert(1, 42).unwrap();
        tx.commit().unwrap();
        drop(db);
        assert!(Journal::open(dir.path()).is_err());
        let db = Database::open(path).unwrap();
        let tx = db.begin_read().unwrap();
        assert_eq!(tx.list_tables().unwrap().count(), 1);
        assert_eq!(
            tx.open_table(table)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            42
        );
    }
}
