//! Common utility traits and functions.
// pub mod int_decomposition;
pub mod word;

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{
        Challenge, ConstraintSystem, Error, Expression, FirstPhase, SecondPhase, VirtualCells,
    },
};

// use crate::table::TxLogFieldTag;
use eth_types::{keccak256, Field, Word};
pub use ethers_core::types::{Address, U256};
pub use gadgets::util::Expr;

/// Cell Manager
pub mod cell_manager;
/// Cell Placement strategies
pub mod cell_placement_strategy;

/// Steal the expression from gate
pub fn query_expression<F: Field, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0.expr())
    });
    expr.unwrap()
}

/// All challenges used in `SuperCircuit`.
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    keccak_input: T,
    lookup_input: T,
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        // Dummy columns are required in the test circuits
        // In some tests there might be no advice columns before the phase, so Halo2 will panic with
        // "No Column<Advice> is used in phase Phase(1) while allocating a new 'Challenge usable
        // after phase Phase(1)'"
        #[cfg(any(test, feature = "test-circuits"))]
        let _dummy_cols = [meta.advice_column(), meta.advice_column_in(SecondPhase)];

        Self {
            keccak_input: meta.challenge_usable_after(FirstPhase),
            lookup_input: meta.challenge_usable_after(SecondPhase),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: Field>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [keccak_input, lookup_input] = query_expression(meta, |meta| {
            [self.keccak_input, self.lookup_input].map(|challenge| meta.query_challenge(challenge))
        });
        Challenges {
            keccak_input,
            lookup_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            keccak_input: layouter.get_challenge(self.keccak_input),
            lookup_input: layouter.get_challenge(self.lookup_input),
        }
    }
}

impl<T: Clone> Challenges<T> {
    /// Returns challenge of `keccak_input`.
    pub fn keccak_input(&self) -> T {
        self.keccak_input.clone()
    }

    /// Returns challenge of `lookup_input`.
    pub fn lookup_input(&self) -> T {
        self.lookup_input.clone()
    }

    /// Returns the challenges indexed by the challenge index
    pub fn indexed(&self) -> [&T; 2] {
        [&self.keccak_input, &self.lookup_input]
    }
}

impl<F: Field> Challenges<Expression<F>> {
    /// Returns powers of randomness
    fn powers_of<const S: usize>(base: Expression<F>) -> [Expression<F>; S] {
        std::iter::successors(base.clone().into(), |power| {
            (base.clone() * power.clone()).into()
        })
        .take(S)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }

    /// Returns powers of randomness for keccak circuit's input
    pub fn keccak_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.keccak_input.clone())
    }

    /// Returns powers of randomness for lookups
    pub fn lookup_input_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.lookup_input.clone())
    }
}

/// SubCircuit is a circuit that performs the verification of a specific part of
/// the full Ethereum block verification.  The SubCircuit's interact with each
/// other via lookup tables and/or shared public inputs.  This type must contain
/// all the inputs required to synthesize this circuit (and the contained
/// table(s) if any).
pub trait SubCircuit<F: Field> {
    /// Configuration of the SubCircuit.
    type Config: SubCircuitConfig<F>;

    /// Returns number of unusable rows of the SubCircuit, which should be
    /// `meta.blinding_factors() + 1`.
    fn unusable_rows() -> usize;

    /// Returns the instance columns required for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
    /// Assign only the columns used by this sub-circuit.  This includes the
    /// columns that belong to the exposed lookup table contained within, if
    /// any; and excludes external tables that this sub-circuit does lookups
    /// to.
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;
}

/// SubCircuit configuration
pub trait SubCircuitConfig<F: Field> {
    /// Config constructor arguments
    type ConfigArgs;

    /// Type constructor
    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;
}

/// Ceiling of log_2(n)
pub fn log2_ceil(n: usize) -> u32 {
    u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32
}

pub(crate) fn keccak(msg: &[u8]) -> Word {
    Word::from_big_endian(keccak256(msg).as_slice())
}
