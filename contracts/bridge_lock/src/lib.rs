use starknet::contract;

#[contract]
mod BridgeLock {
    #[event]
    fn Lock(from: felt252, evm_recipient: felt252, amount: felt252) {}

    #[event]
    fn Release(to: felt252, amount: felt252) {}
}
