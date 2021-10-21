use crate::state::{SecretContract, UnlockRecord, UserLocker};
use cosmwasm_std::{Binary, HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub buttcoin: SecretContract,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    GetUserLocker {
        status: ResponseStatus,
        user_locker: UserLocker,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    GetUserLocker {},
    Receive {
        sender: HumanAddr,
        from: HumanAddr,
        amount: Uint128,
        msg: Binary,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveAnswer {
    CreateOrUpdateLocker { status: ResponseStatus },
    UnlockLocker { status: ResponseStatus },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveMsg {
    CreateOrUpdateLocker {
        content: Option<String>,
        passphrase: Option<String>,
        whitelisted_addresses: Option<Vec<HumanAddr>>,
    },
    UnlockLocker {
        address: HumanAddr,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    Config {
        buttcoin: SecretContract,
    },
    UserLocker {
        content: String,
        locked: bool,
        passphrase: String,
        unlock_records: Vec<UnlockRecord>,
        whitelisted_addresses: Vec<HumanAddr>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Config {},
    UserLocker {
        address: HumanAddr,
        passphrase: String,
    },
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum ResponseStatus {
    Success,
}
