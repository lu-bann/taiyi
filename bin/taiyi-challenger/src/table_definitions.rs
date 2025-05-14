use redb::TableDefinition;

use crate::preconf_request_data::{Bincode, PreconfRequestData};

pub const PRECONF_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("preconf");
pub const CHALLENGE_TABLE: TableDefinition<u64, Bincode<Vec<PreconfRequestData>>> =
    TableDefinition::new("challenge");

#[cfg(test)]
mod tests {
    use std::fs;

    use redb::Database;

    use super::*;

    // Helper function to create a test PreconfRequestData
    fn create_test_data(preconf_type: u8, index: u64) -> PreconfRequestData {
        PreconfRequestData {
            preconf_type,
            preconf_request: format!(r#"{{"id": {}}}"#, index),
            preconf_request_signature: format!("signature{}", index),
        }
    }

    // Helper function to create a temporary database path
    fn temp_db_path(test_name: &str) -> String {
        format!("/tmp/taiyi_test_{}.db", test_name)
    }

    // Helper function to cleanup database files
    fn cleanup_db(path: &str) {
        let _ = fs::remove_file(path);
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
            let data = vec![create_test_data(0, 1), create_test_data(1, 2)];

            // Insert the data
            table.insert(&slot, data.clone()).unwrap();
        }

        // Commit the transaction
        write_tx.commit().unwrap();

        // Start a read transaction and verify data
        let read_tx = db.begin_read().unwrap();
        let table = read_tx.open_table(PRECONF_TABLE).unwrap();

        let slot = 42u64;
        let expected_data = vec![create_test_data(0, 1), create_test_data(1, 2)];

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
    fn test_challenge_table() {
        let db_path = temp_db_path("challenge_table");
        cleanup_db(&db_path); // Ensure clean state

        // Create a database
        let db = Database::create(&db_path).unwrap();

        let slot = 100u64;
        let data = vec![create_test_data(0, 3)];

        // Write transaction
        let write_tx = db.begin_write().unwrap();
        {
            // Open the CHALLENGE_TABLE
            let mut table = write_tx.open_table(CHALLENGE_TABLE).unwrap();

            // Insert the data
            table.insert(&slot, data.clone()).unwrap();
        }

        // Commit the transaction
        write_tx.commit().unwrap();

        // Read transaction
        let read_tx = db.begin_read().unwrap();
        let table = read_tx.open_table(CHALLENGE_TABLE).unwrap();

        // Read the data
        let read_data = table.get(&slot).unwrap().unwrap().value();

        // Verify the data
        assert_eq!(read_data, data);

        // Clean up
        drop(db);
        cleanup_db(&db_path);
    }

    #[test]
    fn test_multiple_slots() {
        let db_path = temp_db_path("multiple_slots");
        cleanup_db(&db_path); // Ensure clean state

        // Create a database
        let db = Database::create(&db_path).unwrap();

        // Write transaction
        let write_tx = db.begin_write().unwrap();
        {
            // Open both tables
            let mut preconf_table = write_tx.open_table(PRECONF_TABLE).unwrap();
            let mut challenge_table = write_tx.open_table(CHALLENGE_TABLE).unwrap();

            // Create and insert test data for multiple slots
            for slot in 1..5 {
                let preconf_data =
                    vec![create_test_data(0, slot * 10), create_test_data(1, slot * 10 + 1)];

                let challenge_data = vec![create_test_data(1, slot * 100)];

                preconf_table.insert(&slot, preconf_data).unwrap();
                challenge_table.insert(&slot, challenge_data).unwrap();
            }
        }

        // Commit the transaction
        write_tx.commit().unwrap();

        // Read transaction
        let read_tx = db.begin_read().unwrap();
        let preconf_table = read_tx.open_table(PRECONF_TABLE).unwrap();
        let challenge_table = read_tx.open_table(CHALLENGE_TABLE).unwrap();

        // Verify the data for each slot
        for slot in 1..5 {
            let preconf_data = preconf_table.get(&slot).unwrap().unwrap().value();
            let challenge_data = challenge_table.get(&slot).unwrap().unwrap().value();

            assert_eq!(preconf_data.len(), 2);
            assert_eq!(preconf_data[0].preconf_type, 0);
            assert_eq!(preconf_data[1].preconf_type, 1);

            assert_eq!(challenge_data.len(), 1);
            assert_eq!(challenge_data[0].preconf_type, 1);
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

        let slot = 200u64;
        let initial_data = vec![create_test_data(0, 1)];

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
            data.push(create_test_data(1, 2));
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

        // Clean up
        drop(db);
        cleanup_db(&db_path);
    }
}
