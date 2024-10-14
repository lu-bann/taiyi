METRICS_SERVER=6060 cargo run -- preconfer --rpc_url="http://127.0.0.1:8545" \
    --beacon_rpc_url="http://127.0.0.1:4000" --taiyi_escrow_contract_addr="0xad4Ce1d2CdBdb84222D519a1FBc8cc181ba28e07" \
    --taiyi_core_contract_addr="0xb01F002F3b21E1e0E81c3023C85aCd02035abCE8" --taiyi_proposer_registry_contract_addr="0x7B7f8371f8bC3e0f148BCeD3a54F89432a0Da5AE" \
    --signer-mod-url="127.0.0.1:8000"\
    --signer-mod-jwt="8d1b71df48ff1971e714156b2aafcac8fc5ea02c6770adc3954557d978ba3439"\
    --commit-boost-config-path="./local/config.toml" \
    --network ./examples/run_taiyi/local