use crate::state::{SecretContract, UserLocker};
use cosmwasm_std::{Binary, HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub buttcoin: SecretContract,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
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
    CreateOrUpdateLocker {
        status: ResponseStatus,
        user_locker: UserLocker,
    },
    GetUserLocker {
        status: ResponseStatus,
        user_locker_response: UserLockerResponse,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveMsg {
    CreateOrUpdateLocker {
        content: Option<String>,
        whitelisted_addresses: Option<Vec<HumanAddr>>,
    },
    GetUserLocker {
        address: HumanAddr,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum ResponseStatus {
    Success,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UserLockerResponse {
    pub content: String,
    pub whitelisted_addresses: Option<Vec<HumanAddr>>,
}
