use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    Store {
        status: ResponseStatus,
        message: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    // Open {},
    Store {
        locker_name: String,
        password: String,
        content: String,
    },
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum ResponseStatus {
    Failure,
    Success,
}
