pub mod core {
    use alloy_sol_types::sol;

    sol! {
            #[sol(rpc)]
            contract TaiyiCore {
                #[derive(Debug)]
                function lockBlockOf(address user) public view returns (uint256);
                #[derive(Debug)]
                function balanceOf(address user) public view returns (uint256);
            }
    }
}
pub use core::TaiyiCore::TaiyiCoreInstance;
