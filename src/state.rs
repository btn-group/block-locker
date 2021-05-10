use cosmwasm_std::{ReadonlyStorage, StdResult, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use schemars::JsonSchema;
use secret_toolkit::serialization::{Bincode2, Serde};
use serde::{Deserialize, Serialize};

// === STORAGE PREFIXES ===
pub const PREFIX_LOCKERS: &[u8] = b"lockers";

// === LOCKERS ===
#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, JsonSchema)]
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

    pub fn set_locker(&mut self, key: &[u8], value: Locker) {
        save(&mut self.storage, &key, &value).ok();
    }
}

pub struct ReadonlyLockersStorage<'a, S: ReadonlyStorage> {
    storage: ReadonlyPrefixedStorage<'a, S>,
}

impl<'a, S: ReadonlyStorage> ReadonlyLockersStorage<'a, S> {
    pub fn from_storage(storage: &'a S) -> Self {
        Self {
            storage: ReadonlyPrefixedStorage::new(PREFIX_LOCKERS, storage),
        }
    }

    fn as_readonly(&self) -> ReadonlyLockersStorageImpl<ReadonlyPrefixedStorage<S>> {
        ReadonlyLockersStorageImpl(&self.storage)
    }
}

/// This struct refactors out the readonly methods that we need for `Balances` and `ReadonlyBalances`
/// in a way that is generic over their mutability.
///
/// This was the only way to prevent code duplication of these methods because of the way
/// that `ReadonlyPrefixedStorage` and `PrefixedStorage` are implemented in `cosmwasm-std`
struct ReadonlyLockersStorageImpl<'a, S: ReadonlyStorage>(&'a S);

impl<'a, S: ReadonlyStorage> ReadonlyLockersStorageImpl<'a, S> {}

// === FUNCTIONS ===

// Returns StdResult<()> resulting from saving an item to storage
// Arguments:
// storage - a mutable reference to the storage this item should go to
// key - a byte slice representing the key to access the stored item
// value - a reference to the item to store
pub fn save<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], value: &T) -> StdResult<()> {
    storage.set(key, &Bincode2::serialize(value)?);
    Ok(())
}
