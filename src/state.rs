use cosmwasm_std::{HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, JsonSchema)]
pub struct UnlockRecord {
    pub address: HumanAddr,
    pub block_height: u64,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, JsonSchema)]
pub struct SecretContract {
    pub address: HumanAddr,
    pub contract_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    pub buttcoin: SecretContract,
    pub buttcoin_balance: Uint128,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct UserLocker {
    pub unlock_records: Vec<UnlockRecord>,
    pub content: String,
    pub locked: bool,
    pub passphrase: String,
    pub whitelisted_addresses: Vec<HumanAddr>,
}
