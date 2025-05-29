use redb::TableDefinition;

use crate::preconf_request_data::{Bincode, PreconfRequestData};

pub const PRECONF_TABLE: TableDefinition<u64, Bincode<Vec<String>>> =
    TableDefinition::new("preconf");

pub const PRECONF_DATA_TABLE: TableDefinition<String, Bincode<PreconfRequestData>> =
    TableDefinition::new("preconf_data");

#[cfg(test)]
mod tests {
    use std::fs;

    use redb::Database;

    use super::*;

    // Helper function to create a temporary database path
    fn temp_db_path(test_name: &str) -> String {
        format!("/tmp/taiyi_prover_test_{}.db", test_name)
    }

    // Helper function to cleanup database files
    fn cleanup_db(path: &str) {
        let _ = fs::remove_file(path);
    }

    // Helper function to create a test PreconfRequestData
    fn create_test_data(preconf_type: u8, index: u64) -> PreconfRequestData {
        PreconfRequestData {
            preconf_type,
            preconf_request: format!(r#"{{"id": {}}}"#, index),
            preconf_request_signature: format!("signature{}", index),
        }
    }

    #[test]
    fn test_preconf_table() {
        let db_path = temp_db_path("preconf_table");
        cleanup_db(&db_path); // Ensure clean state

        // Create a database
        let db = Database::create(&db_path).unwrap();

        // Start a write transaction and insert data
        let write_tx = db.begin_write().unwrap();
        {
            let mut table = write_tx.open_table(PRECONF_TABLE).unwrap();

            // Create test data
            let slot = 42u64;
            let data = vec!["preconf1".to_string(), "preconf2".to_string()];

            // Insert the data
            table.insert(&slot, data.clone()).unwrap();
        }

        // Commit the transaction
        write_tx.commit().unwrap();

        // Start a read transaction and verify data
        let read_tx = db.begin_read().unwrap();
        let table = read_tx.open_table(PRECONF_TABLE).unwrap();

        let slot = 42u64;
        let expected_data = vec!["preconf1".to_string(), "preconf2".to_string()];

        // Read the data
        let read_data = table.get(&slot).unwrap().unwrap().value();

        // Verify the data
        assert_eq!(read_data.len(), expected_data.len());
        assert_eq!(read_data, expected_data);

        // Clean up
        drop(db);
        cleanup_db(&db_path);
    }

    #[test]
    fn test_preconf_data_table() {
        let db_path = temp_db_path("preconf_data_table");
        cleanup_db(&db_path); // Ensure clean state

        // Create a database
        let db = Database::create(&db_path).unwrap();

        let key = "preconf1".to_string();
        let data = create_test_data(0, 1);

        // Write transaction
        let write_tx = db.begin_write().unwrap();
        {
            // Open the PRECONF_DATA_TABLE
            let mut table = write_tx.open_table(PRECONF_DATA_TABLE).unwrap();

            // Insert the data
            table.insert(&key, data.clone()).unwrap();
        }

        // Commit the transaction
        write_tx.commit().unwrap();

        // Read transaction
        let read_tx = db.begin_read().unwrap();
        let table = read_tx.open_table(PRECONF_DATA_TABLE).unwrap();

        // Read the data
        let read_data = table.get(&key).unwrap().unwrap().value();

        // Verify the data
        assert_eq!(read_data, data);

        // Clean up
        drop(db);
        cleanup_db(&db_path);
    }

    #[test]
    fn test_multiple_entries() {
        let db_path = temp_db_path("multiple_entries");
        cleanup_db(&db_path); // Ensure clean state

        // Create a database
        let db = Database::create(&db_path).unwrap();

        // Write transaction
        let write_tx = db.begin_write().unwrap();
        {
            // Open both tables
            let mut preconf_table = write_tx.open_table(PRECONF_TABLE).unwrap();
            let mut preconf_data_table = write_tx.open_table(PRECONF_DATA_TABLE).unwrap();

            // Create and insert test data for PRECONF_TABLE
            for slot in 1..5 {
                let preconf_data =
                    vec![format!("preconf_id_{}_1", slot), format!("preconf_id_{}_2", slot)];
                preconf_table.insert(&slot, preconf_data).unwrap();
            }

            // Create and insert test data for PRECONF_DATA_TABLE
            for i in 1..5 {
                let key = format!("preconf_id_{}", i);
                let data = create_test_data(i as u8 % 2, i);
                preconf_data_table.insert(&key, data).unwrap();
            }
        }

        // Commit the transaction
        write_tx.commit().unwrap();

        // Read transaction
        let read_tx = db.begin_read().unwrap();
        let preconf_table = read_tx.open_table(PRECONF_TABLE).unwrap();
        let preconf_data_table = read_tx.open_table(PRECONF_DATA_TABLE).unwrap();

        // Verify the data for PRECONF_TABLE
        for slot in 1..5 {
            let preconf_data = preconf_table.get(&slot).unwrap().unwrap().value();

            assert_eq!(preconf_data.len(), 2);
            assert_eq!(preconf_data[0], format!("preconf_id_{}_1", slot));
            assert_eq!(preconf_data[1], format!("preconf_id_{}_2", slot));
        }

        // Verify the data for PRECONF_DATA_TABLE
        for i in 1..5 {
            let key = format!("preconf_id_{}", i);
            let data = preconf_data_table.get(&key).unwrap().unwrap().value();

            assert_eq!(data.preconf_type, i as u8 % 2);
            assert_eq!(data.preconf_request, format!(r#"{{"id": {}}}"#, i));
            assert_eq!(data.preconf_request_signature, format!("signature{}", i));
        }

        // Clean up
        drop(db);
        cleanup_db(&db_path);
    }

    #[test]
    fn test_update_existing_data() {
        let db_path = temp_db_path("update_existing");
        cleanup_db(&db_path); // Ensure clean state

        // Create a database
        let db = Database::create(&db_path).unwrap();

        // Test updating PRECONF_TABLE
        {
            let slot = 200u64;
            let initial_data = vec!["preconf1".to_string()];

            // First write transaction - insert initial data
            let write_tx = db.begin_write().unwrap();
            {
                let mut table = write_tx.open_table(PRECONF_TABLE).unwrap();
                table.insert(&slot, initial_data.clone()).unwrap();
            }
            write_tx.commit().unwrap();

            // Read the data and create updated data
            let updated_data = {
                let read_tx = db.begin_read().unwrap();
                let table = read_tx.open_table(PRECONF_TABLE).unwrap();
                let mut data = table.get(&slot).unwrap().unwrap().value();

                // Append new data
                data.push("preconf2".to_string());
                data
            };

            // Second write transaction - update with new data
            let write_tx = db.begin_write().unwrap();
            {
                let mut table = write_tx.open_table(PRECONF_TABLE).unwrap();
                table.insert(&slot, updated_data.clone()).unwrap();
            }
            write_tx.commit().unwrap();

            // Verify the updated data
            let read_tx = db.begin_read().unwrap();
            let table = read_tx.open_table(PRECONF_TABLE).unwrap();
            let read_data = table.get(&slot).unwrap().unwrap().value();

            assert_eq!(read_data.len(), 2);
            assert_eq!(read_data, updated_data);
        }

        // Test updating PRECONF_DATA_TABLE
        {
            let key = "preconf_key".to_string();
            let initial_data = create_test_data(0, 1);

            // First write transaction - insert initial data
            let write_tx = db.begin_write().unwrap();
            {
                let mut table = write_tx.open_table(PRECONF_DATA_TABLE).unwrap();
                table.insert(&key, initial_data.clone()).unwrap();
            }
            write_tx.commit().unwrap();

            // Create updated data
            let updated_data = PreconfRequestData {
                preconf_type: 1,
                preconf_request: r#"{"id": 2, "updated": true}"#.to_string(),
                preconf_request_signature: "updated_signature".to_string(),
            };

            // Second write transaction - update with new data
            let write_tx = db.begin_write().unwrap();
            {
                let mut table = write_tx.open_table(PRECONF_DATA_TABLE).unwrap();
                table.insert(&key, updated_data.clone()).unwrap();
            }
            write_tx.commit().unwrap();

            // Verify the updated data
            let read_tx = db.begin_read().unwrap();
            let table = read_tx.open_table(PRECONF_DATA_TABLE).unwrap();
            let read_data = table.get(&key).unwrap().unwrap().value();

            assert_eq!(read_data.preconf_type, updated_data.preconf_type);
            assert_eq!(read_data.preconf_request, updated_data.preconf_request);
            assert_eq!(read_data.preconf_request_signature, updated_data.preconf_request_signature);
        }

        // Clean up
        drop(db);
        cleanup_db(&db_path);
    }
}
