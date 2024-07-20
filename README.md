# taiyi


## How to work

Taiyi needs to work with signer_module from [commit-boost](https://github.com/Commit-Boost/commit-boost-client). So 
you need to compile commit-boost. Before you start, you need to have a cl and el for the network.

## Signer module

Because the commit-boost is changing so fast with a lot of updates, we recommend you use e6ad292ee43063c16e397e58a9a152482306d16f version of 
the commit-boost for make sure things work correctly.

```
git clone https://github.com/Commit-Boost/commit-boost-client.git
cd commit-boost-client
cargo build --workspace
cp target/debug/signer-module /usr/local/bin/
```

Then you can start signer-module with command below

```
SIGNER_SERVER=8000  \
    CB_CONFIG=./debug/config.example.toml \
    CB_JWTS="{\"luban\":\"8d1b71df48ff1971e714156b2aafcac8fc5ea02c6770adc3954557d978ba3439\"}" \
    SIGNER_LOADER_DIR_KEYS=/path/to/validator-keys/keys \
    SIGNER_LOADER_DIR_SECRETS=/path/to/validator-keys/secrets \
    ./target/debug/signer-module
```


## Taiyi

Once you have your signer-module , cl and el ready, you can start the preconfer with command below.

```
cargo run -- preconfer --rpc_url EL_RPC_URL \
    --beacon_rpc_url CL_RPC_URL \
    --luban_escrow_contract_addr 0xad4Ce1d2CdBdb84222D519a1FBc8cc181ba28e07 # helder contract \
    --luban_core_contract_addr 0xb01F002F3b21E1e0E81c3023C85aCd02035abCE8 # helder contract \ 
    --luban_proposer_registry_contract_addr 0x7B7f8371f8bC3e0f148BCeD3a54F89432a0Da5AE # helder contract \ 
    --commit-boost-url http://127.0.0.1:8000 \
    --commit-boost-id luban \
    --commit-boost-jwt 8d1b71df48ff1971e714156b2aafcac8fc5ea02c6770adc3954557d978ba3439
```