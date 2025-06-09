use taiyi_underwriter::clients::relay_client::{RelayClient, SignedDelegation, DELEGATION_ACTION};

#[ignore = "Fix this test"]
#[test]
fn test_get_signed_delegations() -> eyre::Result<()> {
    let res = get_signed_delegations();
    let signed_delegation: Vec<SignedDelegation> = serde_json::from_str(res)?;
    let signed_delegation = signed_delegation.first().unwrap();
    assert_eq!(signed_delegation.message.action, DELEGATION_ACTION);

    assert_eq!(
        signed_delegation.message.validator_pubkey.to_string(),
        "0x882c02d0c1c30cf9bb84769fc37bf81a73795be9799156ac3a500fba24ddae4f310b47dc27c08e1acdf395a0d9e5ae6a"
    );

    assert_eq!(
        signed_delegation.message.delegatee_pubkey.to_string(),
        "0xa30e3c596a76f109094afbc16689adab5c03fb575213085d3e3a0766d269a961e28dd909312408866c6d481fc8a93522"
    );
    Ok(())
}

fn get_signed_delegations() -> &'static str {
    r#"
    [{
        "message": 
        {
        "action": 0,
        "validator_pubkey": "0x882c02d0c1c30cf9bb84769fc37bf81a73795be9799156ac3a500fba24ddae4f310b47dc27c08e1acdf395a0d9e5ae6a",
        "delegatee_pubkey": "0xa30e3c596a76f109094afbc16689adab5c03fb575213085d3e3a0766d269a961e28dd909312408866c6d481fc8a93522"
        },
        "signature": "0xb067c33c6b8018086ba0b294e069063d185a01116475caa6e4cf36d08d62422ad68ef83ec0b01b4e13dfd95a914f2ed50301e1bfd945d0339b11a0330b06bd532a8bb9cd8017452e1f44f7c64c1ab4888266e87f99c916c90d5fd95614b0dfc4"
    }]"#
}

#[tokio::test]
#[ignore = "devnet is down"]
async fn test_get_current_epoch_validators() -> eyre::Result<()> {
    let relay_client =
        RelayClient::new(vec![
            reqwest::Url::parse("https://relay.taiyi-devnet-0.preconfs.org").unwrap()
        ]);
    let res = relay_client.get_current_epoch_validators().await;
    assert!(res.is_ok());
    Ok(())
}
