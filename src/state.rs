use cosmwasm_std::{HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, JsonSchema)]
pub struct SecretContract {
    pub address: HumanAddr,
    pub contract_hash: String,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, JsonSchema)]
pub struct RequestRecord {
    pub address: HumanAddr,
    pub block_height: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    pub buttcoin: SecretContract,
    pub buttcoin_balance: Uint128,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct UserLocker {
    pub content: String,
    pub request_log: Vec<RequestRecord>,
    pub whitelisted_addresses: Vec<HumanAddr>,
}
