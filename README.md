# Block locker

### Testing locally
```
// 1. Run chain locally
docker run -it --rm -p 26657:26657 -p 26656:26656 -p 1337:1337 -v $(pwd):/root/code --name secretdev enigmampc/secret-network-sw-dev

// 2. Access container via separate terminal window
docker exec -it secretdev /bin/bash

// 3. cd into code folder
cd code

// 4. Store the contract (Specify your keyring. Mine is named test etc.)
secretcli tx compute store buttcoin.wasm.gz --from a --gas 3000000 -y --keyring-backend test
secretcli tx compute store block-locker.wasm.gz --from a --gas 3000000 -y --keyring-backend test

// 5. Init Buttcoin 
CODE_ID=1
INIT='{"name": "Buttcoin", "symbol": "BUTT", "decimals": 6, "initial_balances": [{"address": "secret1qvgmm2u5ptyr0sr34x0uhcd8ujw77x924m5y7m", "amount": "1000000000000000000"},{"address": "secret1jfh0w66dkr0cm0lfpevhqjdswwg4frxqf262g6", "amount": "1000000000000000000"}], "prng_seed": "testing"}'
secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "Buttcoin" -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

// 6. Init Block locker
CODE_ID=2
INIT='{"buttcoin": {"address": "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg", "contract_hash": "4CD7F64B9ADE65200E595216265932A0C7689C4804BE7B4A5F8CEBED250BF7EA"}}'
secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "Block locker" -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

// 7. Create or update locker
// https://www.base64encode.org/
secretcli tx compute execute secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg '{ "send": { "recipient": "secret1u52cx2m6lwqdw42eq3c03mqv6xxun78fvr7qmc", "amount": "1000000", "msg": "eyAiZ2V0X3VzZXJfbG9ja2VyIjogeyJhZGRyZXNzIjogImxldHNnb2JyYW5kb24ifSB9" } }' --from a -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

// 8. Get user locker
secretcli tx compute execute secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg '{ "send": { "recipient": "secret1u52cx2m6lwqdw42eq3c03mqv6xxun78fvr7qmc", "amount": "1000000", "msg": "eyAiZ2V0X3VzZXJfbG9ja2VyIjogeyJhZGRyZXNzIjogInNlY3JldDF3Z2ZlNTJ0ejhodGhlMjM2bmgyOHkwcWFjNGRmOXlnMnFkbXJwciJ9IH0=" } }' --from a -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt
```
