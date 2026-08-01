pub mod arena;
pub mod difficulty;
pub mod kernels;
pub mod scratchpad;
pub mod solver;

pub use arena::EpochArena;
pub use difficulty::next_difficulty;
pub use kernels::EpochKernelParams;
pub use scratchpad::Scratchpad;
pub use solver::{
    difficulty_to_iterations, evaluate_scientific_work, evaluate_scientific_work_at, mine_block,
    operation_count, verify_pow, MAX_POUW_ITERATIONS, POUW_ARITHMETIC_OPERATIONS_PER_CELL,
    POUW_PROTOCOL_VERSION,
};
