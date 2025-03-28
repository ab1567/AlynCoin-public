use core::marker::PhantomData;

pub struct FriVerifier<H> {
    lde_domain_size: usize,
    folding_factor: usize,
    log_num_partitions: usize,
    depth: usize,
    _hasher: PhantomData<H>,
}

impl<H> FriVerifier<H> {
    pub fn new(lde_domain_size: usize, folding_factor: usize) -> Self {
        let depth = (lde_domain_size.trailing_zeros() as usize) - (folding_factor.trailing_zeros() as usize);
        FriVerifier {
            lde_domain_size,
            folding_factor,
            log_num_partitions: 0,
            depth,
            _hasher: PhantomData,
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }
}
