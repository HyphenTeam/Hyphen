use thiserror::Error;

#[derive(Debug, Error)]
pub enum GasError {
    #[error("out of gas: needed {needed}, remaining {remaining}")]
    OutOfGas { needed: u64, remaining: u64 },
}

pub const GAS_BASE: u64 = 1;
pub const GAS_MEMORY_PAGE: u64 = 1000;
pub const GAS_STORAGE_READ: u64 = 200;
pub const GAS_STORAGE_WRITE: u64 = 5000;
pub const GAS_STORAGE_DELETE: u64 = 2500;
pub const GAS_LOG: u64 = 375;
pub const GAS_HASH: u64 = 30;
pub const GAS_DEPLOY_PER_BYTE: u64 = 200;

pub struct GasMeter {
    limit: u64,
    used: u64,
}

impl GasMeter {
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    pub fn consume(&mut self, amount: u64) -> Result<(), GasError> {
        let new_used = self.used.saturating_add(amount);
        if new_used > self.limit {
            return Err(GasError::OutOfGas {
                needed: amount,
                remaining: self.remaining(),
            });
        }
        self.used = new_used;
        Ok(())
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_meter_basic() {
        let mut meter = GasMeter::new(100);
        assert!(meter.consume(50).is_ok());
        assert_eq!(meter.remaining(), 50);
        assert!(meter.consume(51).is_err());
        assert!(meter.consume(50).is_ok());
        assert_eq!(meter.remaining(), 0);
    }
}
