use crate::authorize::authorize;
use crate::msg::ResponseStatus::Success;
use crate::msg::{
    DepositButtcoinAnswer, DepositButtcoinMsg, HandleMsg, InitMsg, ReceiveMsg, UserLockerResponse,
};
use crate::state::{Config, UserLocker};
use cosmwasm_std::{
    from_binary, to_binary, Api, Binary, Env, Extern, HandleResponse, HumanAddr, InitResponse,
    Querier, StdError, StdResult, Storage, Uint128,
};
use rand::Rng;
use secret_toolkit::snip20;
use secret_toolkit::storage::{TypedStore, TypedStoreMut};
use secret_toolkit::utils::pad_handle_result;

// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on response size
pub const AMOUNT_FOR_TRANSACTION: u128 = 1_000_000;
pub const BLOCK_SIZE: usize = 256;
pub const CONFIG_KEY: &[u8] = b"config";
pub const WINNING_NUMBER: u128 = 55;

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

fn amount_of_buttcoin_to_send_to_user(buttcoin_balance: u128) -> u128 {
    let minumum_applicable_balance: u128 = 5;
    let amount: u128 = if buttcoin_balance < minumum_applicable_balance {
        0
    } else {
        let mut rng = rand::thread_rng();
        let random_number: u128 = rng.gen_range(1..=WINNING_NUMBER);
        if random_number == WINNING_NUMBER {
            let random_number_two = rng.gen_range(1..=minumum_applicable_balance);
            buttcoin_balance * random_number_two / minumum_applicable_balance
        } else {
            0
        }
    };
    amount
}

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
    let amount_to_send_to_user: u128 =
        amount_of_buttcoin_to_send_to_user(config.buttcoin_balance.u128() + 1);
    config.buttcoin_balance = Uint128(config.buttcoin_balance.u128() + 1 - amount_to_send_to_user);
    TypedStoreMut::attach(&mut deps.storage)
        .store(CONFIG_KEY, &config)
        .unwrap();

    Ok(HandleResponse {
        messages: vec![snip20::transfer_msg(
            from,
            Uint128(amount_to_send_to_user),
            None,
            BLOCK_SIZE,
            config.buttcoin.contract_hash,
            config.buttcoin.address,
        )?],
        log: vec![],
        data: Some(to_binary(&DepositButtcoinAnswer::CreateOrUpdateLocker {
            status: Success,
            user_locker: user_locker,
        })?),
    })
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
        DepositButtcoinMsg::GetUserLocker { address } => {
            get_user_locker(deps, from, config, address)
        }
    }
}

fn get_user_locker<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    from: HumanAddr,
    mut config: Config,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    // Find or initialize User locker
    let user_locker_store = TypedStore::<UserLocker, S>::attach(&deps.storage);
    let user_locker = user_locker_store
        .load(address.0.as_bytes())
        .unwrap_or(UserLocker {
            content: "".to_string(),
            whitelisted_addresses: vec![],
        });
    let mut user_locker_response: UserLockerResponse = UserLockerResponse {
        content: user_locker.content,
        whitelisted_addresses: Some(user_locker.whitelisted_addresses.clone()),
    };
    if from != address {
        user_locker_response.whitelisted_addresses = None;
        if !user_locker.whitelisted_addresses.contains(&from) {
            user_locker_response.content = "".to_string();
        }
    };

    // Send amount to user
    let amount_to_send_to_user: u128 =
        amount_of_buttcoin_to_send_to_user(config.buttcoin_balance.u128() + 1);
    config.buttcoin_balance = Uint128(config.buttcoin_balance.u128() + 1 - amount_to_send_to_user);
    TypedStoreMut::attach(&mut deps.storage)
        .store(CONFIG_KEY, &config)
        .unwrap();

    Ok(HandleResponse {
        messages: vec![snip20::transfer_msg(
            from,
            Uint128(amount_to_send_to_user),
            None,
            BLOCK_SIZE,
            config.buttcoin.contract_hash,
            config.buttcoin.address,
        )?],
        log: vec![],
        data: Some(to_binary(&DepositButtcoinAnswer::GetUserLocker {
            status: Success,
            user_locker_response: user_locker_response,
        })?),
    })
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
        let whitelisted_addresses: Vec<HumanAddr> = vec![HumanAddr::from("secret12345678910")];
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
            whitelisted_addresses: Some(whitelisted_addresses.clone()),
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
        assert_eq!(
            handle_result_unwrapped.messages,
            vec![snip20::transfer_msg(
                mock_user_address(),
                Uint128(0),
                None,
                BLOCK_SIZE,
                mock_buttcoin().contract_hash,
                mock_buttcoin().address,
            )
            .unwrap()],
        );
        // == * it returns the locker details to the user
        let handle_result_data: DepositButtcoinAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&DepositButtcoinAnswer::CreateOrUpdateLocker {
                status: Success,
                user_locker: UserLocker {
                    content: content.clone(),
                    whitelisted_addresses: whitelisted_addresses.clone()
                },
            })
            .unwrap()
        );

        // when the user has created a locker
        // = when the user sends a request to change the text only
        let new_text: String = "How long can a string be.".to_string();
        let create_or_update_locker_msg = DepositButtcoinMsg::CreateOrUpdateLocker {
            content: Some(new_text.clone()),
            whitelisted_addresses: None,
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
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        // = * It changes the text only
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: DepositButtcoinAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&DepositButtcoinAnswer::CreateOrUpdateLocker {
                status: Success,
                user_locker: UserLocker {
                    content: new_text.clone(),
                    whitelisted_addresses: whitelisted_addresses
                },
            })
            .unwrap()
        );

        // when the user sends a request to change the white listed addresses only
        let new_whitelisted_addresses: Vec<HumanAddr> = vec![HumanAddr::from("secret5")];
        let create_or_update_locker_msg = DepositButtcoinMsg::CreateOrUpdateLocker {
            content: None,
            whitelisted_addresses: Some(new_whitelisted_addresses.clone()),
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
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        // = * It changes the human addresses only
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: DepositButtcoinAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&DepositButtcoinAnswer::CreateOrUpdateLocker {
                status: Success,
                user_locker: UserLocker {
                    content: new_text,
                    whitelisted_addresses: new_whitelisted_addresses
                },
            })
            .unwrap()
        );
        // when the user sends in a request to change both the text and the white listed addresses
        let newer_text: String = "Superconducting.".to_string();
        let newer_whitelisted_addresses: Vec<HumanAddr> = vec![HumanAddr::from("secret5")];
        let create_or_update_locker_msg = DepositButtcoinMsg::CreateOrUpdateLocker {
            content: Some(newer_text.clone()),
            whitelisted_addresses: Some(newer_whitelisted_addresses.clone()),
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
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        // = * It changes the human addresses only
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: DepositButtcoinAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&DepositButtcoinAnswer::CreateOrUpdateLocker {
                status: Success,
                user_locker: UserLocker {
                    content: newer_text,
                    whitelisted_addresses: newer_whitelisted_addresses
                },
            })
            .unwrap()
        );
    }
}
