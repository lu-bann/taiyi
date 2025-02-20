pub const FUNDING_SIGNER_PRIVATE: &str =
    "bf3beef3bd999ba9f2451e06936f0423cd62b815c9233dd3bc90f7e02a1e8673";

pub const PRECONFER_BLS_SK: &str =
    "4942d3308d3fbfbdb977c0bf4c09cb6990aec9fd5ce24709eaf23d96dba71148";
pub const PRECONFER_BLS_PK: &str =
    "a6767d972d21a17843ea94da59461a04d8d0baf92f7c518653170e708f4b21d537db56f9b73810252e0f4e99cc9184cb";
pub const PRECONFER_ECDSA_SK: &str =
    "0xc5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2";

pub const REVERTER_CONTRACT_ADDRESS: &str = "0x50c36a7004fA5479bEADbCE8951bC693e0cb6510";
pub const TAIYI_CONTRACT_ADDRESS: &str = "0xA791D59427B2b7063050187769AC871B497F4b3C";

pub const SLOT_CHECK_INTERVAL_SECONDS: u64 = 12; // Assuming 12 seconds per slot

pub const RESERVE_BLOCKSPACE_PATH: &str = "/commitments/v0/reserve_blockspace";
pub const SUBMIT_TRANSACTION_PATH: &str = "/commitments/v0/submit_transaction";
pub const PRECONF_REQUEST_STATUS_PATH: &str = "/commitments/v0/preconf_request/:preconf_hash";
pub const AVAILABLE_SLOT_PATH: &str = "/commitments/v0/slots";
pub const ESTIMATE_TIP_PATH: &str = "/commitments/v0/estimate_fee";
