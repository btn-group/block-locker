use crate::authorize::authorize;
use crate::msg::ResponseStatus::Success;
use crate::msg::{DepositButtcoinAnswer, DepositButtcoinMsg, HandleMsg, InitMsg, ReceiveMsg};
use crate::state::{Config, UserLocker};
use cosmwasm_std::{
    from_binary, to_binary, Api, Binary, Env, Extern, HandleResponse, HumanAddr, InitResponse,
    Querier, StdError, StdResult, Storage, Uint128,
};
use secret_toolkit::snip20;
use secret_toolkit::storage::{TypedStore, TypedStoreMut};
use secret_toolkit::utils::pad_handle_result;

// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on response size
pub const AMOUNT_FOR_TRANSACTION: u128 = 1_000_000;
pub const BLOCK_SIZE: usize = 256;
pub const CONFIG_KEY: &[u8] = b"config";

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let mut config_store = TypedStoreMut::attach(&mut deps.storage);
    let config: Config = Config {
        buttcoin: msg.buttcoin.clone(),
        buttcoin_balance: Uint128(0),
    };
    config_store.store(CONFIG_KEY, &config)?;

    Ok(InitResponse {
        messages: vec![snip20::register_receive_msg(
            env.contract_code_hash.clone(),
            None,
            BLOCK_SIZE,
            config.buttcoin.contract_hash,
            config.buttcoin.address,
        )?],
        log: vec![],
    })
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    let response = match msg {
        HandleMsg::Receive {
            from, amount, msg, ..
        } => receive(deps, env, from, amount, msg),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

fn deposit_buttcoin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: Uint128,
    hook: Binary,
) -> StdResult<HandleResponse> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
    // Ensure that the sent tokens are Buttcoins
    authorize(config.buttcoin.address.clone(), env.message.sender.clone())?;
    // Ensure that amount sent in is 1 Buttcoin
    if amount != Uint128(AMOUNT_FOR_TRANSACTION) {
        return Err(StdError::generic_err(format!(
            "Amount sent in: {}. Amount required {}.",
            amount,
            Uint128(AMOUNT_FOR_TRANSACTION)
        )));
    }

    let hook_msg = from_binary(&hook)?;
    match hook_msg {
        DepositButtcoinMsg::CreateOrUpdateLocker {
            content,
            whitelisted_addresses,
        } => create_or_update_locker(deps, from, config, content, whitelisted_addresses),
    }
}

fn receive<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: Uint128,
    msg: Binary,
) -> StdResult<HandleResponse> {
    let msg: ReceiveMsg = from_binary(&msg)?;
    match msg {
        ReceiveMsg::DepositButtcoin { hook } => deposit_buttcoin(deps, env, from, amount, hook),
    }
}

// fn try_retrieve<S: Storage, A: Api, Q: Querier>(
//     deps: &mut Extern<S, A, Q>,
//     _env: Env,
//     locker_name: String,
//     password: String,
// ) -> StdResult<HandleResponse> {
//     let mut content: String = "".to_string();
//     let lockers_storage = LockersStorage::from_storage(&mut deps.storage);
//     let locker: Option<Locker> = lockers_storage.get_locker(&locker_name);
//     let mut response_message = String::new();
//     let status: ResponseStatus = if locker.is_none() {
//         response_message.push_str(&format!("That combination does not exist."));
//         Failure
//     } else {
//         let locker_object: Locker = locker.unwrap();
//         if password == locker_object.password {
//             content = locker_object.content;
//             Success
//         } else {
//             response_message.push_str(&format!("That combination does not exist."));
//             Failure
//         }
//     };

//     Ok(HandleResponse {
//         messages: vec![],
//         log: vec![],
//         data: Some(to_binary(&HandleAnswer::Retrieve {
//             content: content,
//             status,
//             message: response_message,
//         })?),
//     })
// }

fn create_or_update_locker<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    from: HumanAddr,
    mut config: Config,
    content: Option<String>,
    whitelisted_addresses: Option<Vec<HumanAddr>>,
) -> StdResult<HandleResponse> {
    // Find or initialize User locker
    let mut user_locker_store = TypedStoreMut::<UserLocker, S>::attach(&mut deps.storage);
    let mut user_locker = user_locker_store
        .load(from.0.as_bytes())
        .unwrap_or(UserLocker {
            whitelisted_addresses: vec![],
            content: "".to_string(),
        });
    if content.is_some() {
        user_locker.content = content.unwrap();
    }
    if whitelisted_addresses.is_some() {
        user_locker.whitelisted_addresses = whitelisted_addresses.unwrap();
    }
    user_locker_store.store(from.0.as_bytes(), &user_locker)?;
    config.buttcoin_balance = Uint128(config.buttcoin_balance.u128() + 1);
    TypedStoreMut::attach(&mut deps.storage)
        .store(CONFIG_KEY, &config)
        .unwrap();

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&DepositButtcoinAnswer::CreateOrUpdateLocker {
            status: Success,
            user_locker: user_locker,
        })?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SecretContract;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::HumanAddr;

    //=== HELPER FUNCTIONS ===

    // fn extract_content(handle_result: HandleResponse) -> String {
    //     let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

    //     match handle_result {
    //         HandleAnswer::Retrieve { content, .. } => content,
    //         _ => panic!("Content not allowed"),
    //     }
    // }

    // fn extract_message(handle_result: HandleResponse) -> String {
    //     let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

    //     match handle_result {
    //         HandleAnswer::Retrieve { message, .. } => message,
    //         HandleAnswer::Store { message, .. } => message,
    //     }
    // }

    // fn ensure_fail(handle_result: HandleResponse) -> bool {
    //     let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

    //     match handle_result {
    //         HandleAnswer::Retrieve { status, .. } => {
    //             matches!(status, ResponseStatus::Failure { .. })
    //         }
    //         HandleAnswer::Store { status, .. } => {
    //             matches!(status, ResponseStatus::Failure { .. })
    //         }
    //     }
    // }

    // fn ensure_success(handle_result: HandleResponse) -> bool {
    //     let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

    //     match handle_result {
    //         HandleAnswer::Retrieve { status, .. } => {
    //             matches!(status, ResponseStatus::Success { .. })
    //         }
    //         HandleAnswer::Store { status, .. } => {
    //             matches!(status, ResponseStatus::Success { .. })
    //         }
    //     }
    // }

    fn init_helper() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env(mock_user_address(), &[]);

        let init_msg = InitMsg {
            buttcoin: mock_buttcoin(),
        };

        (init(&mut deps, env, init_msg), deps)
    }

    fn mock_buttcoin() -> SecretContract {
        SecretContract {
            address: HumanAddr("buttcoin-address".to_string()),
            contract_hash: "buttcoin-contract-hash".to_string(),
        }
    }

    fn mock_user_address() -> HumanAddr {
        HumanAddr::from("some-geezer")
    }

    // === HANDLE TESTS===

    #[test]
    fn test_handle_create_or_update_locker() {
        let content: String = "mnemonic".to_string();
        let wrong_amount: Uint128 = Uint128(AMOUNT_FOR_TRANSACTION - 1);
        // Initialize
        let (init_result, mut deps) = init_helper();

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // when the user has not created a locker yet
        let create_or_update_locker_msg = DepositButtcoinMsg::CreateOrUpdateLocker {
            content: Some(content.clone()),
            whitelisted_addresses: Some(vec![HumanAddr::from("secret12345678910")]),
        };
        let deposit_buttcoin_msg = ReceiveMsg::DepositButtcoin {
            hook: to_binary(&create_or_update_locker_msg).unwrap(),
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&deposit_buttcoin_msg).unwrap(),
        };
        // = when sent token is not Buttcoin
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            receive_msg.clone(),
        );
        // = * it raises an error
        assert_eq!(
            handle_result.unwrap_err(),
            StdError::Unauthorized { backtrace: None }
        );
        // = when sent token is Buttcoin
        // == when sent amount of token is the wrong amount
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: wrong_amount,
            msg: to_binary(&deposit_buttcoin_msg).unwrap(),
        };
        // == * it raises an error
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        assert_eq!(
            handle_result.unwrap_err(),
            StdError::generic_err(format!(
                "Amount sent in: {}. Amount required {}.",
                wrong_amount,
                Uint128(AMOUNT_FOR_TRANSACTION)
            ))
        );
        // == when sent amount of tokens is the right amount
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&deposit_buttcoin_msg).unwrap(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        // == * it sets the locker for the user
        // let user_locker_store = TypedStoreMut::<UserLocker, S>::attach(&mut deps.storage);
        // let user_locker = user_locker_store
        //     .load(from.0.as_bytes())
        //     .unwrap();
        // assert_eq!(user_locker.content, content)
        // assert_eq!(user_locker.whitelisted_addresses, vec![HumanAddr::from("secret12345678910")])

        // == * it increases the balance of BUTT in config by 1
        let config: Config = TypedStoreMut::attach(&mut deps.storage)
            .load(CONFIG_KEY)
            .unwrap();
        assert_eq!(config.buttcoin_balance, Uint128(1));

        // == * it sends a transer message to the user for BUTT
        let handle_result_unwrapped = handle_result.unwrap();
        // assert_eq!(
        //     handle_result_unwrapped.messages,
        //     vec![snip20::set_viewing_key_msg(
        //         VIEWING_KEY.to_string(),
        //         None,
        //         RESPONSE_BLOCK_SIZE,
        //         mock_buttcoin().contract_hash,
        //         mock_buttcoin().address,
        //     )
        //     .unwrap()],
        // );
        // == * it returns the locker details to the user
        let handle_result_data: DepositButtcoinAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&DepositButtcoinAnswer::CreateOrUpdateLocker {
                status: Success,
                user_locker: UserLocker {
                    content: content,
                    whitelisted_addresses: vec![HumanAddr::from("secret12345678910")]
                },
            })
            .unwrap()
        );
    }

    // #[test]
    // fn test_handle_store() {
    //     let content = "mnemonic".to_string();
    //     let locker_name = "tntlocker".to_string();
    //     let password = "bbblllaaazzzeeerrrsss!!!2220002221111".to_string();

    //     // Initialize
    //     let (init_result, mut deps) = init_helper();

    //     assert!(
    //         init_result.is_ok(),
    //         "Init failed: {}",
    //         init_result.err().unwrap()
    //     );

    //     // Store for first time
    //     let store_msg = HandleMsg::Store {
    //         locker_name: locker_name.clone(),
    //         password: password.clone(),
    //         content: content.clone(),
    //     };
    //     let handle_result = handle(&mut deps, mock_env("chuck", &[]), store_msg.clone());
    //     let result = handle_result.unwrap();
    //     assert!(ensure_success(result.clone()));
    //     let success_message = extract_message(result);
    //     success_message.contains("Content stored.");

    //     // Store for second time to same locker name
    //     let handle_result = handle(&mut deps, mock_env("shaq", &[]), store_msg);
    //     let result = handle_result.unwrap();
    //     assert!(ensure_fail(result.clone()));
    //     let error_message = extract_message(result);
    //     error_message.contains("Locker unavailable. Try a different locker name.");

    //     // Store for third time to different locker name
    //     let store_msg = HandleMsg::Store {
    //         locker_name: "locker name 2".to_string(),
    //         password: password,
    //         content: content,
    //     };
    //     let handle_result = handle(&mut deps, mock_env("kenny", &[]), store_msg.clone());
    //     let result = handle_result.unwrap();
    //     assert!(ensure_success(result.clone()));
    //     let success_message = extract_message(result);
    //     success_message.contains("Content stored.");
    // }
}
