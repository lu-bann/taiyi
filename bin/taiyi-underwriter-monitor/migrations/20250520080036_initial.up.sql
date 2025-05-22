CREATE TABLE IF NOT EXISTS underwriter_trades (
    "current_slot" BIGINT NOT NULL,
    "target_slot" BIGINT NOT NULL,
    "total_tip" NUMERIC(78,0) NOT NULL,
    "quoted_gas_price" NUMERIC(78,0) NOT NULL,
    "quoted_blob_price" NUMERIC(78,0) NOT NULL,
    "uuid" UUID NOT NULL,
    "preconf_type" SMALLINT NOT NULL,
    "tx_hashes" BYTEA[],
    "settled" BOOLEAN NOT NULL DEFAULT false,
    "realized_gas_price" NUMERIC(78,0),
    "realized_blob_price" NUMERIC(78,0),
    "block_gas_used" BIGINT,
    "blob_gas_used" BIGINT
);