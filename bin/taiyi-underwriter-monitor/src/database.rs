use std::str::FromStr;

use alloy::primitives::U256;
use eyre::{eyre, Result};
use sqlx::{postgres::PgPoolOptions, types::BigDecimal, Pool, Postgres};
use taiyi_primitives::PreconfRequest;
use uuid::Uuid;

const TABLE_NAME: &str = "underwriter_trades";

pub type TaiyiDBConnection = Pool<Postgres>;

#[derive(Clone, Debug, sqlx::FromRow, Default, PartialEq)]
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
    pub tx_hashes: Vec<[u8; 32]>,
    /// Set to true when inclusion has been checked on-chain
    pub settled: bool,
    /// Realized gas price at settlement time. Null before settlement
    pub realized_gas_price: Option<BigDecimal>,
    /// Realized gas price at settlement time. Null before settlement
    pub realized_blob_price: Option<BigDecimal>,
    /// Block gas used: known after settlement
    pub block_gas_used: Option<i64>,
    /// Blob gas used: known after settlement
    pub blob_gas_used: Option<i64>,
}

impl UnderwriterTradeRow {
    pub fn try_from_preconf_request(
        current_slot: u64,
        uuid: Uuid,
        request: &PreconfRequest,
    ) -> eyre::Result<Self> {
        match request {
            PreconfRequest::TypeA(request) => {
                let preconf_type = 0;
                Ok(Self {
                    current_slot,
                    target_slot: request.target_slot,
                    total_tip: u256_to_big_decimal(request.preconf_tip())?,
                    uuid,
                    quoted_gas_price: u128_to_big_decimal(request.preconf_fee.gas_fee)?,
                    quoted_blob_price: u128_to_big_decimal(request.preconf_fee.blob_gas_fee)?,
                    preconf_type,
                    tx_hashes: request.preconf_tx.iter().map(|tx| tx.hash().0).collect(),
                    settled: false,
                    realized_gas_price: None,
                    realized_blob_price: None,
                    block_gas_used: None,
                    blob_gas_used: None,
                })
            }
            PreconfRequest::TypeB(request) => {
                let preconf_type = 1;
                Ok(Self {
                    current_slot,
                    target_slot: request.allocation.target_slot,
                    total_tip: u256_to_big_decimal(request.preconf_tip())?,
                    uuid,
                    quoted_gas_price: u128_to_big_decimal(request.allocation.preconf_fee.gas_fee)?,
                    quoted_blob_price: u128_to_big_decimal(
                        request.allocation.preconf_fee.blob_gas_fee,
                    )?,
                    preconf_type,
                    tx_hashes: vec![
                        request
                            .transaction
                            .as_ref()
                            .expect("must not be none at this stage")
                            .hash()
                            .0,
                    ],
                    settled: false,
                    realized_gas_price: None,
                    realized_blob_price: None,
                    block_gas_used: None,
                    blob_gas_used: None,
                })
            }
        }
    }

    pub async fn insert_trade_initiation_into_db(self, db_conn: &Pool<Postgres>) -> Result<()> {
        let _ = sqlx::query(
            &format!("\
            INSERT INTO {TABLE_NAME} (
                current_slot, target_slot, total_tip, quoted_gas_price, quoted_blob_price, uuid, preconf_type,tx_hashes \
            ) \
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        )
        .bind(self.current_slot as i64) // $1
        .bind(self.target_slot as i64) // $2
        .bind(self.total_tip) // $3
        .bind(self.quoted_gas_price) // $4
        .bind(self.quoted_blob_price) // $5
        .bind(self.uuid) // $6
        .bind(self.preconf_type) // $7
        .bind(self.tx_hashes) // $8
        .execute(db_conn)
        .await
        .map_err(|e| eyre!("DB error: {e}"))?;
        Ok(())
    }

    pub async fn find_all_by_slot(slot: u64, db_conn: &Pool<Postgres>) -> Result<Vec<Self>> {
        Ok(sqlx::query_as(&format!("SELECT * FROM {TABLE_NAME} WHERE $1 = current_slot;"))
            .bind(slot as i64)
            .fetch_all(db_conn)
            .await?)
    }

    pub async fn update_with_settlement(
        uuid: Uuid,
        realized_gas_price: BigDecimal,
        realized_blob_price: Option<BigDecimal>,
        block_gas_used: i64,
        blob_gas_used: Option<i64>,
        db_conn: &Pool<Postgres>,
    ) -> Result<u64> {
        let query_string: String;
        let query = match realized_blob_price {
            Some(realized_blob_price) => {
                query_string = format!(
                    "UPDATE {TABLE_NAME}
                    SET 
                        settled = TRUE,
                        realized_gas_price = $1,
                        realized_blob_price = $2,
                        block_gas_used = $3,
                        blob_gas_used = $4
                    WHERE uuid = $5"
                );
                sqlx::query(&query_string)
                    .bind(realized_gas_price)
                    .bind(realized_blob_price)
                    .bind(block_gas_used)
                    .bind(blob_gas_used)
                    .bind(uuid)
            }
            None => {
                query_string = format!(
                    "UPDATE {TABLE_NAME}
                    SET 
                        settled = TRUE,
                        realized_gas_price = $1,
                        block_gas_used = $2
                    WHERE uuid = $3",
                );
                sqlx::query(&query_string).bind(realized_gas_price).bind(block_gas_used).bind(uuid)
            }
        };
        Ok(query.execute(db_conn).await?.rows_affected())
    }
}

pub fn u128_to_big_decimal(x: u128) -> eyre::Result<BigDecimal> {
    Ok(BigDecimal::from_str(&x.to_string())?)
}

pub fn u256_to_big_decimal(x: U256) -> eyre::Result<BigDecimal> {
    Ok(BigDecimal::from_str(&x.to_string())?)
}

pub async fn get_db_connection(url: &str) -> Result<TaiyiDBConnection> {
    Ok(PgPoolOptions::new().max_connections(5).connect(url).await?)
}

#[cfg(test)]
mod test {
    use taiyi_primitives::{PreconfRequestTypeA, PreconfRequestTypeB};
    use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner as _};

    use super::*;

    const POSTGRES_USER: &str = "postgres";
    const POSTGRES_PASSWORD: &str = "postgres";
    const POSTGRES_DBNAME: &str = "postgres";

    /// Connects & runs migrations on the test DB
    async fn init_db(conn_string: &str) -> Result<Pool<Postgres>> {
        let db_conn = PgPoolOptions::new().max_connections(5).connect(conn_string).await?;
        sqlx::migrate!("./migrations").run(&db_conn).await?;
        Ok(db_conn)
    }

    fn get_conn_string(host_ip: String, host_port: String) -> String {
        format!("postgres://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{host_ip}:{host_port}/{POSTGRES_DBNAME}")
    }

    #[tokio::test]
    async fn test_init_db() -> eyre::Result<()> {
        // start test postgresql server container
        let container = postgres::Postgres::default().start().await?;
        let host_ip = container.get_host().await?;
        let host_port = container.get_host_port_ipv4(5432).await?;

        let db_conn = init_db(&get_conn_string(host_ip.to_string(), host_port.to_string())).await?;

        let empty_table_result = UnderwriterTradeRow::find_all_by_slot(123, &db_conn).await?;

        assert_eq!(empty_table_result.len(), 0, "table should be newly created");
        Ok(())
    }

    #[tokio::test]
    async fn test_from_preconf_type_a_request() -> eyre::Result<()> {
        // Read json data
        let request = {
            let request: PreconfRequestTypeA =
                serde_json::from_str(&std::fs::read_to_string("test-data/type-a.json")?)?;
            PreconfRequest::TypeA(request)
        };

        let uuid = Uuid::new_v4();
        let row = UnderwriterTradeRow::try_from_preconf_request(101, uuid, &request)?;

        let PreconfRequest::TypeA(request) = request else { unreachable!() };

        assert_eq!(row.current_slot, 101);
        assert_eq!(row.target_slot, 105);
        assert_eq!(row.total_tip, u256_to_big_decimal(request.preconf_tip())?);
        assert_eq!(row.preconf_type, 0);
        assert_eq!(row.uuid, uuid);
        assert_eq!(row.quoted_gas_price, u128_to_big_decimal(request.preconf_fee.gas_fee)?);
        assert_eq!(row.quoted_blob_price, u128_to_big_decimal(request.preconf_fee.blob_gas_fee)?);
        assert_eq!(row.tx_hashes.len(), 1);
        assert_eq!(row.tx_hashes.first().unwrap(), request.preconf_tx.first().unwrap().hash());
        assert!(!row.settled);
        assert_eq!(row.realized_gas_price, None);
        assert_eq!(row.realized_blob_price, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_from_preconf_type_b_request() -> eyre::Result<()> {
        // Read json data
        let request = {
            let request: PreconfRequestTypeB =
                serde_json::from_str(&std::fs::read_to_string("test-data/type-b.json")?)?;
            PreconfRequest::TypeB(request)
        };

        let uuid = Uuid::new_v4();
        let row = UnderwriterTradeRow::try_from_preconf_request(101, uuid, &request)?;

        let PreconfRequest::TypeB(request) = request else { unreachable!() };

        assert_eq!(row.current_slot, 101);
        assert_eq!(row.target_slot, 105);
        assert_eq!(row.total_tip, u256_to_big_decimal(request.preconf_tip())?);
        assert_eq!(row.preconf_type, 1);
        assert_eq!(row.uuid, uuid);
        assert_eq!(
            row.quoted_gas_price,
            u128_to_big_decimal(request.allocation.preconf_fee.gas_fee)?
        );
        assert_eq!(
            row.quoted_blob_price,
            u128_to_big_decimal(request.allocation.preconf_fee.blob_gas_fee)?
        );
        assert_eq!(row.tx_hashes.len(), 1);
        assert_eq!(row.tx_hashes.first().unwrap(), request.transaction.unwrap().hash());
        assert!(!row.settled);
        assert_eq!(row.realized_gas_price, None);
        assert_eq!(row.realized_blob_price, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_insert_into_db() -> eyre::Result<()> {
        // start test postgresql server container
        let container = postgres::Postgres::default().start().await?;
        let host_ip = container.get_host().await?;
        let host_port = container.get_host_port_ipv4(5432).await?;

        let db_conn = init_db(&get_conn_string(host_ip.to_string(), host_port.to_string())).await?;

        // Read json data
        let request = {
            let request: PreconfRequestTypeB =
                serde_json::from_str(&std::fs::read_to_string("test-data/type-b.json")?)?;
            PreconfRequest::TypeB(request)
        };

        let uuid = Uuid::new_v4();
        let row = UnderwriterTradeRow::try_from_preconf_request(101, uuid, &request)?;

        row.clone().insert_trade_initiation_into_db(&db_conn).await?;

        let retrieved = UnderwriterTradeRow::find_all_by_slot(101, &db_conn).await?;
        assert_eq!(retrieved.len(), 1);

        let retrieved = retrieved.first().unwrap().clone();

        assert_eq!(row, retrieved);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_with_settlement() -> eyre::Result<()> {
        // start test postgresql server container
        let container = postgres::Postgres::default().start().await?;
        let host_ip = container.get_host().await?;
        let host_port = container.get_host_port_ipv4(5432).await?;

        let db_conn = init_db(&get_conn_string(host_ip.to_string(), host_port.to_string())).await?;

        // Read json data
        let request = {
            let request: PreconfRequestTypeB =
                serde_json::from_str(&std::fs::read_to_string("test-data/type-b.json")?)?;
            PreconfRequest::TypeB(request)
        };

        let uuid = Uuid::new_v4();
        let row = UnderwriterTradeRow::try_from_preconf_request(101, uuid, &request)?;

        row.clone().insert_trade_initiation_into_db(&db_conn).await?;

        UnderwriterTradeRow::update_with_settlement(
            uuid,
            BigDecimal::from(234),
            Some(BigDecimal::from(567)),
            300,
            Some(100),
            &db_conn,
        )
        .await?;

        // expected values for the updated row are all the same except for these 3:
        let row = UnderwriterTradeRow {
            settled: true,
            realized_gas_price: Some(BigDecimal::from(234)),
            realized_blob_price: Some(BigDecimal::from(567)),
            block_gas_used: Some(300),
            blob_gas_used: Some(100),
            ..row
        };

        let retrieved = UnderwriterTradeRow::find_all_by_slot(101, &db_conn).await?;
        assert_eq!(retrieved.len(), 1);

        let retrieved = retrieved.first().unwrap().clone();
        assert_eq!(row, retrieved);

        Ok(())
    }
}
