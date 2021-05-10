use cosmwasm_std::{ReadonlyStorage, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// === STORAGE PREFIXES ===
pub const PREFIX_LOCKERS: &[u8] = b"lockers";

// === LOCKERS ===
#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct Locker {
    pub password: String,
    pub data: String,
}

pub struct Lockers<'a, S: Storage> {
    storage: PrefixedStorage<'a, S>,
}

impl<'a, S: Storage> Lockers<'a, S> {
    pub fn from_storage(storage: &'a mut S) -> Self {
        Self {
            storage: PrefixedStorage::new(PREFIX_LOCKERS, storage),
        }
    }
}

pub struct ReadonlyLockers<'a, S: ReadonlyStorage> {
    storage: ReadonlyPrefixedStorage<'a, S>,
}

impl<'a, S: ReadonlyStorage> ReadonlyLockers<'a, S> {
    pub fn from_storage(storage: &'a S) -> Self {
        Self {
            storage: ReadonlyPrefixedStorage::new(PREFIX_LOCKERS, storage),
        }
    }

    fn as_readonly(&self) -> ReadonlyLockersImpl<ReadonlyPrefixedStorage<S>> {
        ReadonlyLockersImpl(&self.storage)
    }
}

/// This struct refactors out the readonly methods that we need for `Balances` and `ReadonlyBalances`
/// in a way that is generic over their mutability.
///
/// This was the only way to prevent code duplication of these methods because of the way
/// that `ReadonlyPrefixedStorage` and `PrefixedStorage` are implemented in `cosmwasm-std`
struct ReadonlyLockersImpl<'a, S: ReadonlyStorage>(&'a S);

impl<'a, S: ReadonlyStorage> ReadonlyLockersImpl<'a, S> {}
