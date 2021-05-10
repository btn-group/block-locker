use cosmwasm_std::{ReadonlyStorage, StdResult, Storage};
use cosmwasm_storage::PrefixedStorage;
use secret_toolkit::serialization::{Bincode2, Serde};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// === STORAGE PREFIXES ===
pub const PREFIX_LOCKERS: &[u8] = b"lockers";

// === LOCKERS ===
#[derive(Serialize, Debug, Deserialize, Clone, PartialEq)]
pub struct Locker {
    pub password: String,
    pub content: String,
}

pub struct LockersStorage<'a, S: Storage> {
    storage: PrefixedStorage<'a, S>,
}

impl<'a, S: Storage> LockersStorage<'a, S> {
    pub fn from_storage(storage: &'a mut S) -> Self {
        Self {
            storage: PrefixedStorage::new(PREFIX_LOCKERS, storage),
        }
    }

    fn as_readonly(&self) -> ReadonlyLockersStorageImpl<PrefixedStorage<S>> {
        ReadonlyLockersStorageImpl(&self.storage)
    }

    pub fn get_locker(&self, key: &String) -> Option<Locker> {
        self.as_readonly().get(key)
    }

    pub fn set_locker(&mut self, key: &[u8], value: Locker) {
        save(&mut self.storage, &key, &value).ok();
    }
}

// This struct refactors out the readonly methods in a way that is generic over their mutability.
// This was the only way to prevent code duplication of these methods because of the way
/// that `ReadonlyPrefixedStorage` and `PrefixedStorage` are implemented in `cosmwasm-std`
struct ReadonlyLockersStorageImpl<'a, S: ReadonlyStorage>(&'a S);

impl<'a, S: ReadonlyStorage> ReadonlyLockersStorageImpl<'a, S> {
    pub fn get(&self, key: &String) -> Option<Locker> {
        let alias: Option<Locker> = may_load(self.0, &key.as_bytes()).ok().unwrap();
        alias
    }
}

// === FUNCTIONS ===

// Returns StdResult<()> resulting from saving an item to storage
// Arguments:
// storage - a mutable reference to the storage this item should go to
// key - a byte slice representing the key to access the stored item
// value - a reference to the item to store
fn save<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], value: &T) -> StdResult<()> {
    storage.set(key, &Bincode2::serialize(value)?);
    Ok(())
}

fn may_load<T: DeserializeOwned, S: ReadonlyStorage>(
    storage: &S,
    key: &[u8],
) -> StdResult<Option<T>> {
    match storage.get(key) {
        Some(value) => Bincode2::deserialize(&value).map(Some),
        None => Ok(None),
    }
}
