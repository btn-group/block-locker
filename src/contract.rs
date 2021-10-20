use crate::authorize::authorize;
use crate::msg::ResponseStatus::Success;
use crate::msg::{
    HandleMsg, InitMsg, QueryAnswer, QueryMsg, ReceiveAnswer, ReceiveMsg, UserLockerResponse,
};
use crate::state::{Config, UserLocker};
use cosmwasm_std::{
    from_binary, to_binary, Api, Binary, CosmosMsg, Env, Extern, HandleResponse, HumanAddr,
    InitResponse, Querier, QueryResult, StdError, StdResult, Storage, Uint128,
};
use rand::Rng;
use secret_toolkit::snip20;
use secret_toolkit::storage::{TypedStore, TypedStoreMut};
use secret_toolkit::utils::pad_handle_result;

// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on response size
pub const AMOUNT_FOR_TRANSACTION: u128 = 1_000_000;
pub const BLOCK_SIZE: usize = 256;
pub const CONFIG_KEY: &[u8] = b"config";
pub const WINNING_NUMBER: u128 = 5;

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

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    match msg {
        QueryMsg::Config {} => query_config(deps),
    }
}

// So what's this really for then? I guess this is really for a return for the user to get some of their BUTT back and this is for people setting and getting...
// It's a way to keep things circulating... and because it's called when a user requests a view and when they create or update, it's hard to say for sure who did what.
// Consideing no balance is shown as well, it's not really gambling. It's just a manner of circulating the funds back to people.
fn amount_of_buttcoin_to_send_to_user(buttcoin_balance: u128) -> u128 {
    let mut rng = rand::thread_rng();
    let random_number: u128 = rng.gen_range(1, 55);
    let mut random_number_two = rng.gen_range(1, 6);
    if random_number != WINNING_NUMBER {
        random_number_two = 0
    }
    buttcoin_balance * random_number_two / 5
}

fn create_or_update_locker<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    from: HumanAddr,
    config: Config,
    content: Option<String>,
    whitelisted_addresses: Option<Vec<String>>,
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
            user_locker: user_locker,
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
    from: HumanAddr,
    config: Config,
    address: String,
) -> StdResult<HandleResponse> {
    let address = HumanAddr::from(address);
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
        if !user_locker
            .whitelisted_addresses
            .contains(&from.as_str().to_string())
        {
            user_locker_response.content = "".to_string();
        }
        user_locker_response.whitelisted_addresses = None;
    };

    Ok(HandleResponse {
        messages: factor_amount_to_send_to_user(deps, config, from),
        log: vec![],
        data: Some(to_binary(&ReceiveAnswer::GetUserLocker {
            status: Success,
            user_locker_response: user_locker_response,
        })?),
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
    let response = match msg {
        ReceiveMsg::CreateOrUpdateLocker {
            content,
            whitelisted_addresses,
        } => create_or_update_locker(deps, from, config, content, whitelisted_addresses),
        ReceiveMsg::GetUserLocker { address } => get_user_locker(deps, from, config, address),
    };
    response
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
        let whitelisted_addresses: Vec<String> = vec!["secret12345678910".to_string()];
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
        // == * it sets the locker for the user
        // let user_locker_store = TypedStoreMut::<UserLocker, S>::attach(&mut deps.storage);
        // let user_locker = user_locker_store
        //     .load(from.0.as_bytes())
        //     .unwrap();
        // assert_eq!(user_locker.content, content)
        // assert_eq!(user_locker.whitelisteStringes, vec!["secret12345678910"])

        // == * it increases the balance of BUTT in config by 1
        let config: Config = TypedStoreMut::attach(&mut deps.storage)
            .load(CONFIG_KEY)
            .unwrap();
        assert_eq!(config.buttcoin_balance, Uint128(AMOUNT_FOR_TRANSACTION));

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
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::CreateOrUpdateLocker {
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
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: Some(new_text.clone()),
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
        // = * It changes the text only
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::CreateOrUpdateLocker {
                status: Success,
                user_locker: UserLocker {
                    content: new_text.clone(),
                    whitelisted_addresses: whitelisted_addresses
                },
            })
            .unwrap()
        );

        // when the user sends a request to change the white listed addresses only
        let new_whitelisted_addresses: Vec<String> = vec!["secret5".to_string()];
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: None,
            whitelisted_addresses: Some(new_whitelisted_addresses.clone()),
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
        // = * It changes the human addresses only
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::CreateOrUpdateLocker {
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
        let newer_whitelisted_addresses: Vec<String> = vec!["secret5".to_string()];
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: Some(newer_text.clone()),
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
        // = * It changes the human addresses only
        let handle_result_unwrapped = handle_result.unwrap();
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::CreateOrUpdateLocker {
                status: Success,
                user_locker: UserLocker {
                    content: newer_text,
                    whitelisted_addresses: newer_whitelisted_addresses
                },
            })
            .unwrap()
        );

        // when the user sends in more than 3 addresses
        let newer_text: String = "Superconducting.".to_string();
        let newer_whitelisted_addresses: Vec<String> = vec![
            "secret5".to_string(),
            "secret2".to_string(),
            "secret3".to_string(),
            "secret1".to_string(),
        ];
        let create_or_update_locker_msg = ReceiveMsg::CreateOrUpdateLocker {
            content: Some(newer_text.clone()),
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
    }

    #[test]
    fn test_handle_get_user_locker() {
        let content: String = "mnemonic".to_string();
        let whitelisted_addresses: Vec<String> = vec!["secret12345678910".to_string()];
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

        // === when a user without access to the locker requests the locker
        let get_user_locker_msg = ReceiveMsg::GetUserLocker {
            address: mock_user_address().to_string(),
        };
        let receive_msg = HandleMsg::Receive {
            sender: HumanAddr::from("letsgobrandon"),
            from: HumanAddr::from("letsgobrandon"),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&get_user_locker_msg).unwrap(),
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
        assert_eq!(config.buttcoin_balance, Uint128(2 * AMOUNT_FOR_TRANSACTION));

        // === * it sends a transer message to the user for BUTT
        assert_eq!(
            handle_result_unwrapped.messages,
            vec![snip20::transfer_msg(
                HumanAddr::from("letsgobrandon"),
                Uint128(0),
                None,
                BLOCK_SIZE,
                mock_buttcoin().contract_hash,
                mock_buttcoin().address,
            )
            .unwrap()],
        );
        // === * it sends a UserLockerResponse with a blank string and no whitelisted addresses
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::GetUserLocker {
                status: Success,
                user_locker_response: UserLockerResponse {
                    content: "".to_string(),
                    whitelisted_addresses: None
                },
            })
            .unwrap()
        );

        // === when a user with access to the locker requests the locker but is not the owner
        let get_user_locker_msg = ReceiveMsg::GetUserLocker {
            address: mock_user_address().to_string(),
        };
        let receive_msg = HandleMsg::Receive {
            sender: HumanAddr::from(whitelisted_addresses[0].clone()),
            from: HumanAddr::from(whitelisted_addresses[0].clone()),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&get_user_locker_msg).unwrap(),
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
        assert_eq!(config.buttcoin_balance, Uint128(3 * AMOUNT_FOR_TRANSACTION));

        // === * it sends a transer message to the user for BUTT
        assert_eq!(
            handle_result_unwrapped.messages,
            vec![snip20::transfer_msg(
                HumanAddr::from(whitelisted_addresses[0].clone()),
                Uint128(0),
                None,
                BLOCK_SIZE,
                mock_buttcoin().contract_hash,
                mock_buttcoin().address,
            )
            .unwrap()],
        );
        // === * it sends a UserLockerResponse with a blank string and no whitelisted addresses
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::GetUserLocker {
                status: Success,
                user_locker_response: UserLockerResponse {
                    content: content.clone(),
                    whitelisted_addresses: None
                },
            })
            .unwrap()
        );

        // === when the owner accesses their locker
        let get_user_locker_msg = ReceiveMsg::GetUserLocker {
            address: mock_user_address().to_string(),
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&get_user_locker_msg).unwrap(),
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
        assert_eq!(config.buttcoin_balance, Uint128(4 * AMOUNT_FOR_TRANSACTION));

        // === * it sends a transer message to the user for BUTT
        assert_eq!(
            handle_result_unwrapped.messages,
            vec![snip20::transfer_msg(
                mock_user_address().clone(),
                Uint128(0),
                None,
                BLOCK_SIZE,
                mock_buttcoin().contract_hash,
                mock_buttcoin().address,
            )
            .unwrap()],
        );
        // === * it sends a UserLockerResponse with a blank string and whitelisted addresses
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::GetUserLocker {
                status: Success,
                user_locker_response: UserLockerResponse {
                    content: content,
                    whitelisted_addresses: Some(whitelisted_addresses)
                },
            })
            .unwrap()
        );

        // === when a user tries to access a locker that does not exist
        let get_user_locker_msg = ReceiveMsg::GetUserLocker {
            address: "thislockerdoesnotexist".to_string(),
        };
        let receive_msg = HandleMsg::Receive {
            sender: mock_user_address(),
            from: mock_user_address(),
            amount: Uint128(AMOUNT_FOR_TRANSACTION),
            msg: to_binary(&get_user_locker_msg).unwrap(),
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
        assert_eq!(config.buttcoin_balance, Uint128(5 * AMOUNT_FOR_TRANSACTION));

        // === * it sends a transer message to the user for BUTT
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
        // === * it sends a UserLockerResponse with a blank string and no whitelisted addresses
        let handle_result_data: ReceiveAnswer =
            from_binary(&handle_result_unwrapped.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&handle_result_data).unwrap(),
            to_binary(&ReceiveAnswer::GetUserLocker {
                status: Success,
                user_locker_response: UserLockerResponse {
                    content: "".to_string(),
                    whitelisted_addresses: None
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
        }
    }
}
