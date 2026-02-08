use crate::errors::SyncError;

pub type SyncResult<T> = Result<T, SyncError>;

#[derive(Debug, Clone, Copy)]
pub struct SyncProgress {
    pub latest_block: u64,
    pub latest_commitment_block: u64,
    pub commitments: usize,
    pub nullifiers: usize,
    pub unshields: usize,
}

pub trait SyncSource {
    fn name(&self) -> &'static str;
}
