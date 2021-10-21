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
secretcli tx compute execute secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg '{ "send": { "recipient": "secret1nrv47252c7hsvs26kwyc90vuy2wp3mk3cqr065", "amount": "1000000", "msg": "eyAiY3JlYXRlX29yX3VwZGF0ZV9sb2NrZXIiOiB7ImNvbnRlbnQiOiAiVGhpcyBpcyBvbmUgZmFrZSBzdGVwIGZvciBtYW4uIiwgInBhc3NwaHJhc2UiOiAiZ2V0IHdheHhpbmF0ZWQiLCAid2hpdGVsaXN0ZWRfYWRkcmVzc2VzIjogWyJzZWNyZXQxamZoMHc2NmRrcjBjbTBsZnBldmhxamRzd3dnNGZyeHFmMjYyZzYiXX0gfQ==" } }' --from a -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

// 8. Get user locker
secretcli tx compute execute secret1nrv47252c7hsvs26kwyc90vuy2wp3mk3cqr065 '{ "get_user_locker": {} }' --from a -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

// 9. Query config
secretcli query compute query secret1nrv47252c7hsvs26kwyc90vuy2wp3mk3cqr065 '{"config": {}}'

// 10. Query user locker
secretcli query compute query secret1nrv47252c7hsvs26kwyc90vuy2wp3mk3cqr065 '{"user_locker": { "address": "secret1qvgmm2u5ptyr0sr34x0uhcd8ujw77x924m5y7m", "passphrase": "abcde fghijk."}}'

// 11. Unlock locker
secretcli tx compute execute secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg '{ "send": { "recipient": "secret1nrv47252c7hsvs26kwyc90vuy2wp3mk3cqr065", "amount": "1000000", "msg": "eyAidW5sb2NrX2xvY2tlciI6IHsiYWRkcmVzcyI6ICJzZWNyZXQxcXZnbW0ydTVwdHlyMHNyMzR4MHVoY2Q4dWp3Nzd4OTI0bTV5N20ifSB9" } }' --from b -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

// 12. Query user locker
secretcli query compute query secret1nrv47252c7hsvs26kwyc90vuy2wp3mk3cqr065 '{"user_locker": { "address": "secret1qvgmm2u5ptyr0sr34x0uhcd8ujw77x924m5y7m", "passphrase": "get waxxinated"}}'
```
