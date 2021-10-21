use crate::authorize::authorize;
use crate::msg::ResponseStatus::Success;
use crate::msg::{
    HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg, ReceiveAnswer, ReceiveMsg,
};
use crate::state::{Config, UnlockRecord, UserLocker};
use cosmwasm_std::{
    from_binary, to_binary, Api, Binary, CosmosMsg, Env, Extern, HandleResponse, HumanAddr,
    InitResponse, Querier, QueryResult, StdError, StdResult, Storage, Uint128,
};
use secret_toolkit::snip20;
use secret_toolkit::storage::{TypedStore, TypedStoreMut};
use secret_toolkit::utils::{pad_handle_result, pad_query_result};

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
        HandleMsg::GetUserLocker {} => get_user_locker(deps, env),
        HandleMsg::Receive {
            from, amount, msg, ..
        } => receive(deps, env, from, amount, msg),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::Config {} => query_config(deps),
        QueryMsg::UserLocker {
            address,
            passphrase,
        } => query_user_locker(deps, address, passphrase),
    };
    pad_query_result(response, BLOCK_SIZE)
}

// This is just to keep funds circulating within the eco system
fn amount_of_buttcoin_to_send_to_user(buttcoin_balance: u128) -> u128 {
    if buttcoin_balance == 555 * AMOUNT_FOR_TRANSACTION {
        buttcoin_balance
    } else {
        0
    }
}

fn create_or_update_locker<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    from: HumanAddr,
    config: Config,
    content: Option<String>,
    passphrase: Option<String>,
    whitelisted_addresses: Option<Vec<HumanAddr>>,
) -> StdResult<HandleResponse> {
    // Find or initialize User locker
    let mut user_locker_store = TypedStoreMut::<UserLocker, S>::attach(&mut deps.storage);
    let mut user_locker = user_locker_store
        .load(from.0.as_bytes())
        .unwrap_or(UserLocker {
            unlock_records: vec![],
            content: "".to_string(),
            locked: true,
            passphrase: "".to_string(),
            whitelisted_addresses: vec![],
        });
    if content.is_some() {
        user_locker.content = content.unwrap();
    }
    user_locker.locked = true;
    if passphrase.is_some() {
        user_locker.passphrase = passphrase.unwrap();
    }
    if whitelisted_addresses.is_some() {
        user_locker.whitelisted_addresses = whitelisted_addresses.unwrap();
        if user_locker.whitelisted_addresses.len() > 3 {
            return Err(StdError::generic_err(format!(
                "Maximum of 3 whitelisted_addresses."
            )));
        }
    }
    user_locker_store.store(from.0.as_bytes(), &user_locker)?;

    Ok(HandleResponse {
        messages: factor_amount_to_send_to_user(deps, config, from),
        log: vec![],
        data: Some(to_binary(&ReceiveAnswer::CreateOrUpdateLocker {
            status: Success,
        })?),
    })
}

fn factor_amount_to_send_to_user<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    mut config: Config,
    user_address: HumanAddr,
) -> Vec<CosmosMsg> {
    // Send amount to user
    let amount_to_send_to_user: u128 =
        amount_of_buttcoin_to_send_to_user(config.buttcoin_balance.u128() + AMOUNT_FOR_TRANSACTION);
    config.buttcoin_balance =
        Uint128(config.buttcoin_balance.u128() + AMOUNT_FOR_TRANSACTION - amount_to_send_to_user);
    TypedStoreMut::attach(&mut deps.storage)
        .store(CONFIG_KEY, &config)
        .unwrap();
    vec![snip20::transfer_msg(
        user_address,
        Uint128(amount_to_send_to_user),
        None,
        BLOCK_SIZE,
        config.buttcoin.contract_hash,
        config.buttcoin.address,
    )
    .unwrap()]
}

fn get_user_locker<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    // Find or initialize User locker
    let user_locker_store = TypedStore::<UserLocker, S>::attach(&deps.storage);
    let user_locker = user_locker_store
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(UserLocker {
            content: "".to_string(),
            locked: true,
            passphrase: "".to_string(),
            unlock_records: vec![],
            whitelisted_addresses: vec![],
        });

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::GetUserLocker {
            status: Success,
            user_locker: user_locker,
        })?),
    })
}

fn query_user_locker<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: HumanAddr,
    passphrase: String,
) -> QueryResult {
    // Find or initialize User locker
    let user_locker_store = TypedStore::<UserLocker, S>::attach(&deps.storage);
    let user_locker = user_locker_store
        .load(address.0.as_bytes())
        .unwrap_or(UserLocker {
            content: "".to_string(),
            locked: true,
            passphrase: "".to_string(),
            unlock_records: vec![],
            whitelisted_addresses: vec![],
        });
    let mut content_to_return: String = "".to_string();
    let mut locked_to_return: bool = true;
    let mut passphrase_to_return: String = "".to_string();
    let mut unlock_records_to_return: Vec<UnlockRecord> = vec![];
    let mut whitelisted_addresses_to_return: Vec<HumanAddr> = vec![];
    if !user_locker.locked {
        if user_locker.passphrase == passphrase {
            content_to_return = user_locker.content;
            locked_to_return = false;
            passphrase_to_return = user_locker.passphrase;
            unlock_records_to_return = user_locker.unlock_records;
            whitelisted_addresses_to_return = user_locker.whitelisted_addresses;
        }
    };
    to_binary(&QueryAnswer::UserLocker {
        content: content_to_return,
        locked: locked_to_return,
        passphrase: passphrase_to_return,
        unlock_records: unlock_records_to_return,
        whitelisted_addresses: whitelisted_addresses_to_return,
    })
}

fn query_config<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;

    to_binary(&QueryAnswer::Config {
        buttcoin: config.buttcoin,
    })
}

fn receive<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: Uint128,
    msg: Binary,
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

    let msg: ReceiveMsg = from_binary(&msg)?;
    match msg {
        ReceiveMsg::CreateOrUpdateLocker {
            content,
            passphrase,
            whitelisted_addresses,
        } => create_or_update_locker(
            deps,
            from,
            config,
            content,
            passphrase,
            whitelisted_addresses,
        ),
        ReceiveMsg::UnlockLocker { address } => unlock_locker(deps, env, from, address, config),
    }
}

fn unlock_locker<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    address: HumanAddr,
    config: Config,
) -> StdResult<HandleResponse> {
    // Find or initialize User locker
    let mut user_locker_store = TypedStoreMut::<UserLocker, S>::attach(&mut deps.storage);
    let mut user_locker = user_locker_store
        .load(address.0.as_bytes())
        .unwrap_or(UserLocker {
            unlock_records: vec![],
            content: "".to_string(),
            locked: true,
            passphrase: "".to_string(),
            whitelisted_addresses: vec![],
        });
    if user_locker.locked {
        if user_locker.whitelisted_addresses.contains(&from) {
            user_locker.locked = false;
            user_locker.unlock_records.push(UnlockRecord {
                address: from.clone(),
                block_height: env.block.height,
            });
            user_locker_store.store(address.0.as_bytes(), &user_locker)?;
        }
    }

    Ok(HandleResponse {
        messages: factor_amount_to_send_to_user(deps, config, from),
        log: vec![],
        data: Some(to_binary(&ReceiveAnswer::UnlockLocker { status: Success })?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SecretContract;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::HumanAddr;

    //=== HELPER FUNCTIONS ===
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
        let passphrase: String = "passphrase".to_string();
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
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: Some(content.clone()),
            passphrase: Some(passphrase.clone()),
            whitelisted_addresses: Some(whitelisted_addresses.clone()),
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
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
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
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
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();

        // == * it increases the balance of BUTT in config by 1
        let config: Config = TypedStoreMut::attach(&mut deps.storage)
            .load(CONFIG_KEY)
            .unwrap();
        assert_eq!(config.buttcoin_balance, Uint128(AMOUNT_FOR_TRANSACTION));

        // == * it sends a transer message to the user for BUTT
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

        // == * it sets the locker with the correct details
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: content.clone(),
                    locked: true,
                    passphrase: passphrase.clone(),
                    unlock_records: vec![],
                    whitelisted_addresses: whitelisted_addresses.clone()
                },
            })
            .unwrap()
        );

        // when the user has created a locker
        // = when the user sends a request to change the text only
        let new_text: String = "How long can a string be.".to_string();
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: Some(new_text.clone()),
            passphrase: None,
            whitelisted_addresses: None,
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        // = * It changes the content only
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::CreateOrUpdateLocker { status: Success }).unwrap()
        );
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: new_text.clone(),
                    locked: true,
                    passphrase: passphrase.clone(),
                    unlock_records: vec![],
                    whitelisted_addresses: whitelisted_addresses.clone()
                },
            })
            .unwrap()
        );

        // when the user sends a request to change the white listed addresses only
        let new_whitelisted_addresses: Vec<HumanAddr> = vec![HumanAddr::from("secret5")];
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: None,
            passphrase: None,
            whitelisted_addresses: Some(new_whitelisted_addresses.clone()),
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        )
        .unwrap();
        // = * It changes the human addresses only
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: new_text.clone(),
                    locked: true,
                    passphrase: passphrase.clone(),
                    unlock_records: vec![],
                    whitelisted_addresses: new_whitelisted_addresses.clone()
                },
            })
            .unwrap()
        );

        // when the user sends in a request to change the passphrase only
        let new_passphrase: String = "famine".to_string();
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: None,
            passphrase: Some(new_passphrase.clone()),
            whitelisted_addresses: None,
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        )
        .unwrap();
        // = * It changes the passphrase only
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: new_text.clone(),
                    locked: true,
                    passphrase: new_passphrase.clone(),
                    unlock_records: vec![],
                    whitelisted_addresses: new_whitelisted_addresses.clone()
                },
            })
            .unwrap()
        );

        // when the user sends in more than 3 addresses
        let newer_whitelisted_addresses: Vec<HumanAddr> = vec![
            HumanAddr::from("secret5"),
            HumanAddr::from("secret2"),
            HumanAddr::from("secret3"),
            HumanAddr::from("secret1"),
        ];
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: None,
            passphrase: None,
            whitelisted_addresses: Some(newer_whitelisted_addresses.clone()),
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        // = * It raises an error
        assert_eq!(
            handle_result.unwrap_err(),
            StdError::generic_err(format!("Maximum of 3 whitelisted_addresses."))
        );

        // = when locker is unlocked
        let unlock_locker_msg = ReceiveMsg::UnlockLocker {
            address: mock_user_address(),
        };
        let receive_msg = HandleMsg::Receive {
            sender: HumanAddr::from("secret5"),
            from: HumanAddr::from("secret5"),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&unlock_locker_msg).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        )
        .unwrap();
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: new_text.clone(),
                    locked: false,
                    passphrase: new_passphrase.clone(),
                    unlock_records: vec![UnlockRecord {
                        address: HumanAddr::from("secret5"),
                        block_height: 12_345
                    }],
                    whitelisted_addresses: new_whitelisted_addresses.clone()
                },
            })
            .unwrap()
        );
        // == when user updates their locker
        // == * it locks the locker again
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: None,
            passphrase: None,
            whitelisted_addresses: None,
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
        };
        handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        )
        .unwrap();
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: new_text,
                    locked: true,
                    passphrase: new_passphrase.clone(),
                    unlock_records: vec![UnlockRecord {
                        address: HumanAddr::from("secret5"),
                        block_height: 12_345
                    }],
                    whitelisted_addresses: new_whitelisted_addresses
                },
            })
            .unwrap()
        );
    }

    #[test]
    fn test_handle_receive_unlock_locker() {
        let content: String = "mnemonic".to_string();
        let passphrase: String = "passphrase".to_string();
        let whitelisted_addresses: Vec<HumanAddr> = vec![HumanAddr::from("secret12345678910")];
        let wrong_amount: Uint128 = Uint128(AMOUNT_FOR_TRANSACTION - 1);
        // Initialize
        let (init_result, mut deps) = init_helper();

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // when user tries to unlock a locker that does not exist
        let unlock_locker_msg = ReceiveMsg::UnlockLocker {
            address: HumanAddr::from("rightonqueue"),
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&unlock_locker_msg).unwrap(),
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
            msg: to_binary(&unlock_locker_msg).unwrap(),
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
            msg: to_binary(&unlock_locker_msg).unwrap(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        // === * it increases the balance of BUTT in config by 1
        let config: Config = TypedStoreMut::attach(&mut deps.storage)
            .load(CONFIG_KEY)
            .unwrap();
        assert_eq!(config.buttcoin_balance, Uint128(AMOUNT_FOR_TRANSACTION));

        // === * it sends a transer message to the user for BUTT
        assert_eq!(
            handle_result_unwrapped.messages,
            vec![snip20::transfer_msg(
                mock_user_address(),
                Uint128(0),
                None,
                BLOCK_SIZE,
                config.buttcoin.contract_hash,
                config.buttcoin.address,
            )
            .unwrap()],
        );
        // === * it sends success message but doesn't do anything
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::UnlockLocker { status: Success }).unwrap()
        );

        // when locker exists
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: Some(content.clone()),
            passphrase: Some(passphrase.clone()),
            whitelisted_addresses: Some(whitelisted_addresses.clone()),
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        handle_result.unwrap();
        // = when non-whitelisted user tries to unlock locker
        let unlock_locker_msg = ReceiveMsg::UnlockLocker {
            address: mock_user_address(),
        };
        let receive_msg = HandleMsg::Receive {
            sender: HumanAddr::from("1"),
            from: HumanAddr::from("1"),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&unlock_locker_msg).unwrap(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        // == * it sends success message
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::UnlockLocker { status: Success }).unwrap()
        );
        // == * it does not unlock the locker
        // == * it does not keep a record of trying to unlock
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: content.clone(),
                    locked: true,
                    passphrase: passphrase.clone(),
                    unlock_records: vec![],
                    whitelisted_addresses: whitelisted_addresses.clone()
                },
            })
            .unwrap()
        );

        // == when they are whitelisted to unlock the locker
        let unlock_locker_msg = ReceiveMsg::UnlockLocker {
            address: mock_user_address(),
        };
        let receive_msg = HandleMsg::Receive {
            sender: HumanAddr::from("secret12345678910"),
            from: HumanAddr::from("secret12345678910"),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&unlock_locker_msg).unwrap(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        // == * it sends a success message
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::UnlockLocker { status: Success }).unwrap()
        );
        // == * it unlocks the locker
        // == * it keeps a record of trying to unlock
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: content,
                    locked: false,
                    passphrase: passphrase,
                    unlock_records: vec![UnlockRecord {
                        address: HumanAddr::from("secret12345678910"),
                        block_height: 12_345
                    }],
                    whitelisted_addresses: whitelisted_addresses
                },
            })
            .unwrap()
        );
    }

    #[test]
    fn test_handle_get_user_locker() {
        let content: String = "mnemonic".to_string();
        let passphrase: String = "passphrase".to_string();
        let whitelisted_addresses: Vec<HumanAddr> = vec![HumanAddr::from("secret12345678910")];
        let wrong_amount: Uint128 = Uint128(AMOUNT_FOR_TRANSACTION - 1);
        // Initialize
        let (init_result, mut deps) = init_helper();

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: Some(content.clone()),
            passphrase: Some(passphrase.clone()),
            whitelisted_addresses: Some(whitelisted_addresses.clone()),
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
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
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
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
            msg: to_binary(&create_or_update_locker_msg).unwrap(),
        };
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            receive_msg.clone(),
        );
        handle_result.unwrap();

        // === when a user without a locker requests their locker
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();
        // === * it does not increase the balance of BUTT in config by 1
        let config: Config = TypedStoreMut::attach(&mut deps.storage)
            .load(CONFIG_KEY)
            .unwrap();
        assert_eq!(config.buttcoin_balance, Uint128(1 * AMOUNT_FOR_TRANSACTION));

        // === * it does not send a transer message to the user for BUTT
        assert_eq!(handle_result_unwrapped.messages, vec![],);
        // === * it sends a UserLocker with a blank string and no whitelisted addresses
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: content,
                    locked: true,
                    passphrase: passphrase,
                    unlock_records: vec![],
                    whitelisted_addresses: whitelisted_addresses
                },
            })
            .unwrap()
        );

        // === when a user with no locker requests
        let get_user_locker_msg = HandleMsg::GetUserLocker {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_buttcoin().address, &[]),
            get_user_locker_msg.clone(),
        );
        let handle_result_unwrapped = handle_result.unwrap();

        // === * it sends a UserLockerResponse with a blank string and no whitelisted addresses
        let handle_result_data: HandleAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&HandleAnswer::GetUserLocker {
                status: Success,
                user_locker: UserLocker {
                    content: "".to_string(),
                    locked: true,
                    passphrase: "".to_string(),
                    unlock_records: vec![],
                    whitelisted_addresses: vec![]
                },
            })
            .unwrap()
        );
    }

    // === QUERY TESTS ===

    #[test]
    fn test_query_config() {
        let (_init_result, deps) = init_helper();
        let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY).unwrap();
        let query_result = query(&deps, QueryMsg::Config {}).unwrap();
        let query_answer: QueryAnswer = from_binary(&query_result).unwrap();
        match query_answer {
            QueryAnswer::Config { buttcoin } => {
                assert_eq!(buttcoin, config.buttcoin);
            }
            QueryAnswer::UserLocker {
                content: _,
                locked: _,
                passphrase: _,
                whitelisted_addresses: _,
                unlock_records: _,
            } => {}
        }
    }
}
