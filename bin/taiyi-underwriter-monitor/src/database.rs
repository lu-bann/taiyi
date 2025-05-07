use std::str::FromStr;

use alloy_primitives::U256;
use eyre::{eyre, Result};
use sqlx::{postgres::PgPoolOptions, types::BigDecimal, Pool, Postgres};
use taiyi_primitives::PreconfRequest;
use uuid::Uuid;

pub type TaiyiDBConnection = Pool<Postgres>;

#[derive(Clone, Debug, sqlx::FromRow, Default)]
pub struct UnderwriterTradeRow {
    #[sqlx(try_from = "i64")]
    pub current_slot: u64,
    #[sqlx(try_from = "i64")]
    pub target_slot: u64,

    pub total_tip: BigDecimal,
    /// 0 = Type A, 1 = Type B
    pub preconf_type: i16,
    pub uuid: Uuid,
    pub quoted_gas_price: BigDecimal,
    pub quoted_blob_price: BigDecimal,
    /// The hash of the transaction. Can be empty only after reserve blockspace,
    /// and must have length >= 1 after submission of Type A and Type B transactions.
    /// Used to check when the tx is actually included
    /// SQL type: BYTEA[]
    /// example insert:
    /// ```postgresql
    ///     INSERT INTO table_name (other_fields,..., tx_hash)
    ///     VALUES (other_fields_values,..., ARRAY[
    ///         decode('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'),
    ///         decode('4bf0c0fe4789e8a9d3347ff4d244e2e2cb758bb6c0c5b4b939db8a93d1c5cd25', 'hex')
    ///     ]);
    /// ```
    /// example select for row for a certain tx hash:
    ///     SELECT * FROM table_name
    ///     WHERE decode('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex') = ANY(tx_hash);
    // pub tx_hash: Option<Vec<Vec<u8>>>,
    pub tx_hash: Vec<[u8; 32]>,
    /// Set to true when inclusion has been checked on-chain
    pub settled: bool,
    /// Realized gas price at settlement time. Null before settlement
    pub realized_gas_price: Option<BigDecimal>,
    /// Realized gas price at settlement time. Null before settlement
    pub realized_blob_price: Option<BigDecimal>,
}

impl UnderwriterTradeRow {
    const TABLE_NAME: &str = "underwriter_trades";
    pub fn from_preconf_request(current_slot: u64, uuid: Uuid, request: &PreconfRequest) -> Self {
        match request {
            PreconfRequest::TypeA(request) => {
                let preconf_type = 0;
                Self {
                    current_slot,
                    target_slot: request.target_slot,
                    total_tip: u256_to_big_decimal(request.preconf_tip()),
                    uuid,
                    quoted_gas_price: u128_to_big_decimal(request.preconf_fee.gas_fee),
                    quoted_blob_price: u128_to_big_decimal(request.preconf_fee.blob_gas_fee),
                    preconf_type,
                    tx_hash: request.preconf_tx.iter().map(|tx| tx.hash().0).collect(),
                    settled: false,
                    realized_gas_price: None,
                    realized_blob_price: None,
                }
            }
            PreconfRequest::TypeB(request) => {
                let preconf_type = 1;
                Self {
                    current_slot,
                    target_slot: request.allocation.target_slot,
                    total_tip: u256_to_big_decimal(request.preconf_tip()),
                    uuid,
                    quoted_gas_price: u128_to_big_decimal(request.allocation.preconf_fee.gas_fee),
                    quoted_blob_price: u128_to_big_decimal(
                        request.allocation.preconf_fee.blob_gas_fee,
                    ),
                    preconf_type,
                    tx_hash: vec![request.transaction.as_ref().unwrap().hash().0],
                    settled: false,
                    realized_gas_price: None,
                    realized_blob_price: None,
                }
            }
        }
    }

    pub async fn insert_trade_initiation_into_db(self, db_conn: &Pool<Postgres>) -> Result<()> {
        let _ = sqlx::query(
            "\
            INSERT INTO underwriter_trades (
                current_slot, target_slot, total_tip, quoted_gas_price, quoted_blob_price, uuid, preconf_type,tx_hash \
            ) \
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(self.current_slot as i64) // $1
        .bind(self.target_slot as i64) // $2
        .bind(self.total_tip) // $3
        .bind(self.quoted_gas_price) // $4
        .bind(self.quoted_blob_price) // $5
        .bind(self.uuid) // $6
        .bind(self.preconf_type) // $7
        .bind(self.tx_hash) // $8
        .execute(db_conn)
        .await
        .map_err(|e| eyre!("DB error: {e}"))?;
        Ok(())
    }

    pub async fn find_all_by_slot(slot: u64, db_conn: &Pool<Postgres>) -> Result<Vec<Self>> {
        Ok(sqlx::query_as(&format!("SELECT * FROM {} WHERE $1 = current_slot;", Self::TABLE_NAME))
            .bind(slot as i64)
            .fetch_all(db_conn)
            .await?)
    }

    pub async fn update_with_settlement(
        uuid: Uuid,
        realized_gas_price: BigDecimal,
        realized_blob_price: Option<BigDecimal>,
        db_conn: &Pool<Postgres>,
    ) -> Result<u64> {
        let query_string: String;
        let query = match realized_blob_price {
            Some(realized_blob_price) => {
                query_string = format!(
                    "UPDATE {}
                    SET settled = TRUE,
                    realized_gas_price = $1,
                    realized_blob_price = $2
                    WHERE uuid = $3",
                    Self::TABLE_NAME
                );
                sqlx::query(&query_string)
                    .bind(realized_gas_price)
                    .bind(realized_blob_price)
                    .bind(uuid)
            }
            None => {
                query_string = format!(
                    "UPDATE {}
                    SET settled = TRUE,
                    realized_gas_price = $1,
                    WHERE uuid = $3",
                    Self::TABLE_NAME
                );
                sqlx::query(&query_string).bind(realized_gas_price).bind(uuid)
            }
        };
        Ok(query.execute(db_conn).await?.rows_affected())
    }

    pub async fn init_db_schema(db_conn: &Pool<sqlx::Postgres>) -> Result<()> {
        let create_table_str = generate_create_table(
            Self::TABLE_NAME,
            vec![
                ("current_slot", "BIGINT"),
                ("target_slot", "BIGINT"),
                ("total_tip", "NUMERIC(78,0)"),
                ("quoted_gas_price", "NUMERIC(78,0)"),
                ("quoted_blob_price", "NUMERIC(78,0)"),
                ("uuid", "UUID"),
                ("preconf_type", "SMALLINT"),
                ("tx_hash", "BYTEA[]"),
            ],
            true,
        );

        let _ = sqlx::query(&create_table_str).execute(db_conn).await?;
        Ok(())
    }
}

pub fn generate_create_table(
    table_name: &str,
    fields: Vec<(&str, &str)>,
    if_not_exists: bool,
) -> String {
    let columns: Vec<_> =
        fields.iter().map(|(name, value)| format!("\"{name}\" {value}")).collect();

    let if_not_exists = if if_not_exists { "IF NOT EXISTS" } else { "" };
    format!("CREATE TABLE {} {} (\n{}\n);", if_not_exists, table_name, columns.join(",\n"))
}

pub fn u128_to_big_decimal(x: u128) -> BigDecimal {
    BigDecimal::from_str(&x.to_string()).expect("bug in either bigdecimal or u128 string methods")
}

pub fn u256_to_big_decimal(x: U256) -> BigDecimal {
    BigDecimal::from_str(&x.to_string()).expect("bug in either bigdecimal or u128 string methods")
}

pub async fn get_db_connection(url: &str) -> Result<TaiyiDBConnection> {
    Ok(PgPoolOptions::new().max_connections(5).connect(url).await?)
}
