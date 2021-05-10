use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    Retrieve {
        content: String,
        message: String,
        status: ResponseStatus,
    },
    Store {
        message: String,
        status: ResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    Retrieve {
        locker_name: String,
        password: String,
    },
    Store {
        content: String,
        locker_name: String,
        password: String,
    },
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum ResponseStatus {
    Failure,
    Success,
}
