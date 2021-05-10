use crate::msg::ResponseStatus::{Failure, Success};
use crate::msg::{HandleAnswer, HandleMsg, ResponseStatus};
use crate::state::{Locker, LockersStorage};

use cosmwasm_std::{
    to_binary, Api, Env, Extern, HandleResponse, InitResponse, Querier, StdResult, Storage,
};
use secret_toolkit::utils::pad_handle_result;
use std::string::String;

// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on response size
pub const BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    _env: Env,
) -> StdResult<InitResponse> {
    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    let response = match msg {
        HandleMsg::Store {
            locker_name,
            password,
            content,
        } => try_store(deps, env, locker_name, password, content),
        // HandleMsg::Open { count } => try_open(deps, env, count),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

fn try_store<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    locker_name: String,
    password: String,
    content: String,
) -> StdResult<HandleResponse> {
    let locker_name_byte_slice: &[u8] = locker_name.as_bytes();
    let mut lockers_storage = LockersStorage::from_storage(&mut deps.storage);
    let locker: Option<Locker> = lockers_storage.get_locker(&locker_name);
    let mut response_message = String::new();
    let status: ResponseStatus = if locker.is_none() {
        let new_locker = Locker {
            password: password,
            content: content,
        };
        lockers_storage.set_locker(locker_name_byte_slice, new_locker);
        response_message.push_str(&format!("Content stored."));
        Success
    } else {
        response_message.push_str(&format!("Locker unavailable. Try a different locker name."));
        Failure
    };

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Store {
            status,
            message: response_message,
        })?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::from_binary;
    use cosmwasm_std::testing::*;

    //=== HELPER FUNCTIONS ===

    fn extract_message(handle_result: HandleResponse) -> String {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Store { status: _, message } => message,
        }
    }

    fn ensure_fail(handle_result: HandleResponse) -> bool {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Store { status, message: _ } => {
                matches!(status, ResponseStatus::Failure { .. })
            }
        }
    }

    fn ensure_success(handle_result: HandleResponse) -> bool {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Store { status, message: _ } => {
                matches!(status, ResponseStatus::Success { .. })
            }
        }
    }

    fn init_helper() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("admin", &[]);
        (init(&mut deps, env), deps)
    }

    // === HANDLE TESTS===

    #[test]
    fn test_handle_store() {
        // Initialize
        let (init_result, mut deps) = init_helper();

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Store for first time
        let store_msg = HandleMsg::Store {
            locker_name: "locker name".to_string(),
            password: "password".to_string(),
            content: "mnemonic".to_string(),
        };
        let handle_result = handle(&mut deps, mock_env("chuck", &[]), store_msg.clone());
        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        let success_message = extract_message(result);
        success_message.contains("Content stored.");

        // Store for second time to same locker name
        let store_msg = HandleMsg::Store {
            locker_name: "locker name".to_string(),
            password: "password".to_string(),
            content: "mnemonic".to_string(),
        };
        let handle_result = handle(&mut deps, mock_env("shaq", &[]), store_msg.clone());
        let result = handle_result.unwrap();
        assert!(ensure_fail(result.clone()));
        let error_message = extract_message(result);
        error_message.contains("Locker unavailable. Try a different locker name.");

        // Store for third time to different locker name
        let store_msg = HandleMsg::Store {
            locker_name: "locker name 2".to_string(),
            password: "password".to_string(),
            content: "mnemonic".to_string(),
        };
        let handle_result = handle(&mut deps, mock_env("kenny", &[]), store_msg.clone());
        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        let success_message = extract_message(result);
        success_message.contains("Content stored.");
    }
}
