use tracing::error;

pub fn log_error<T, E: ToString>(result: Result<T, E>, msg: &str) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) => {
            error!("{msg}: {}", err.to_string());
            None
        }
    }
}
