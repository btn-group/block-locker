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
        HandleMsg::Retrieve {
            locker_name,
            password,
        } => try_retrieve(deps, env, locker_name, password),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

fn try_retrieve<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    locker_name: String,
    password: String,
) -> StdResult<HandleResponse> {
    let mut content: String = "".to_string();
    let lockers_storage = LockersStorage::from_storage(&mut deps.storage);
    let locker: Option<Locker> = lockers_storage.get_locker(&locker_name);
    let mut response_message = String::new();
    let status: ResponseStatus = if locker.is_none() {
        response_message.push_str(&format!("That combination does not exist."));
        Failure
    } else {
        let locker_object: Locker = locker.unwrap();
        if password == locker_object.password {
            content = locker_object.content;
            Success
        } else {
            response_message.push_str(&format!("That combination does not exist."));
            Failure
        }
    };

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Retrieve {
            content: content,
            status,
            message: response_message,
        })?),
    })
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

    fn extract_content(handle_result: HandleResponse) -> String {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Retrieve { content, .. } => content,
            _ => panic!("Content not allowed"),
        }
    }

    fn extract_message(handle_result: HandleResponse) -> String {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Retrieve { message, .. } => message,
            HandleAnswer::Store { message, .. } => message,
        }
    }

    fn ensure_fail(handle_result: HandleResponse) -> bool {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Retrieve { status, .. } => {
                matches!(status, ResponseStatus::Failure { .. })
            }
            HandleAnswer::Store { status, .. } => {
                matches!(status, ResponseStatus::Failure { .. })
            }
        }
    }

    fn ensure_success(handle_result: HandleResponse) -> bool {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Retrieve { status, .. } => {
                matches!(status, ResponseStatus::Success { .. })
            }
            HandleAnswer::Store { status, .. } => {
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
    fn test_handle_retrieve() {
        let content: String = "mnemonic".to_string();
        let storer: String = "chuck".to_string();
        let different_user: String = "ernie".to_string();
        let locker_name = "tntlocker".to_string();
        let password = "bbblllaaazzzeeerrrsss!!!2220002221111".to_string();

        // Initialize
        let (init_result, mut deps) = init_helper();

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Store for first time
        let store_msg = HandleMsg::Store {
            locker_name: locker_name.clone(),
            password: password.clone(),
            content: content.clone(),
        };
        let handle_result = handle(&mut deps, mock_env(storer.clone(), &[]), store_msg.clone());
        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        let success_message = extract_message(result);
        success_message.contains("Content stored.");

        // Retrieve as same user with correct lockername and password
        let retrieve_msg = HandleMsg::Retrieve {
            locker_name: locker_name.clone(),
            password: password.clone(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(storer.clone(), &[]),
            retrieve_msg.clone(),
        );
        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        let success_message = extract_message(result.clone());
        success_message.contains("");
        let retrieved_content = extract_content(result);
        retrieved_content.contains(&content);

        // Retrieve as different user with correct lockername and password
        let handle_result = handle(&mut deps, mock_env(different_user, &[]), retrieve_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        let success_message = extract_message(result.clone());
        success_message.contains("");
        let retrieved_content = extract_content(result);
        retrieved_content.contains(&content);

        // Retrieve as same user with wrong lockername and correct password
        let retrieve_msg = HandleMsg::Retrieve {
            locker_name: "wrong locker name".to_string(),
            password: password.clone(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(storer.clone(), &[]),
            retrieve_msg.clone(),
        );
        let result = handle_result.unwrap();
        assert!(ensure_fail(result.clone()));
        let error_message = extract_message(result);
        error_message.contains("That combination does not exist.");

        // Retrieve as same user with correct lockername and wrong password
        let retrieve_msg = HandleMsg::Retrieve {
            locker_name: locker_name,
            password: "wrong password".to_string(),
        };
        let handle_result = handle(&mut deps, mock_env(storer, &[]), retrieve_msg.clone());
        let result = handle_result.unwrap();
        assert!(ensure_fail(result.clone()));
        let error_message = extract_message(result);
        error_message.contains("That combination does not exist.");
    }

    #[test]
    fn test_handle_store() {
        let content = "mnemonic".to_string();
        let locker_name = "tntlocker".to_string();
        let password = "bbblllaaazzzeeerrrsss!!!2220002221111".to_string();

        // Initialize
        let (init_result, mut deps) = init_helper();

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Store for first time
        let store_msg = HandleMsg::Store {
            locker_name: locker_name.clone(),
            password: password.clone(),
            content: content.clone(),
        };
        let handle_result = handle(&mut deps, mock_env("chuck", &[]), store_msg.clone());
        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        let success_message = extract_message(result);
        success_message.contains("Content stored.");

        // Store for second time to same locker name
        let handle_result = handle(&mut deps, mock_env("shaq", &[]), store_msg);
        let result = handle_result.unwrap();
        assert!(ensure_fail(result.clone()));
        let error_message = extract_message(result);
        error_message.contains("Locker unavailable. Try a different locker name.");

        // Store for third time to different locker name
        let store_msg = HandleMsg::Store {
            locker_name: "locker name 2".to_string(),
            password: password,
            content: content,
        };
        let handle_result = handle(&mut deps, mock_env("kenny", &[]), store_msg.clone());
        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        let success_message = extract_message(result);
        success_message.contains("Content stored.");
    }
}
