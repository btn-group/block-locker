use cosmwasm_std::{Api, Env, Extern, HandleResponse, InitResponse, Querier, StdResult, Storage};

use crate::msg::HandleMsg;

pub fn init<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    _env: Env,
) -> StdResult<InitResponse> {
    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        // HandleMsg::Store {} => try_store(deps, env),
        // HandleMsg::Open { count } => try_open(deps, env, count),
    }
}

// #[cfg(test)]
