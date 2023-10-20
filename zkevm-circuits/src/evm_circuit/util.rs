pub use crate::util::{
    query_expression,
    word::{Word, WordExpr},
    Challenges, Expr,
};
use eth_types::{Field, U256};
use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Assigned, Column, Error},
    poly::Rotation,
};
use itertools::Itertools;

pub(crate) mod constraint_builder;

pub use gadgets::util::{and, not, or, select, sum};

pub(crate) use crate::util::cell_manager::Cell;

pub struct CachedRegion<'r, 'b, F: Field> {
    region: &'r mut Region<'b, F>,
    advice: Vec<Vec<F>>,
    challenges: &'r Challenges<Value<F>>,
    advice_columns: Vec<Column<Advice>>,
    width_start: usize,
    height_start: usize,
}

impl<'r, 'b, F: Field> CachedRegion<'r, 'b, F> {
    /// This method replicates the assignment of 1 row at height_start (which
    /// must be already assigned via the CachedRegion) into a range of rows
    /// indicated by offset_begin, offset_end. It can be used as a "quick"
    /// path for assignment for repeated padding rows.
    pub fn replicate_assignment_for_range<A, AR>(
        &mut self,
        annotation: A,
        offset_begin: usize,
        offset_end: usize,
    ) -> Result<(), Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        for (v, column) in self
            .advice
            .iter()
            .map(|values| values[0])
            .zip_eq(self.advice_columns.iter())
        {
            if v.is_zero_vartime() {
                continue;
            }
            let annotation: &String = &annotation().into();
            for offset in offset_begin..offset_end {
                self.region
                    .assign_advice(|| annotation, *column, offset, || Value::known(v))?;
            }
        }

        Ok(())
    }

    /// Assign an advice column value (witness).
    pub fn assign_advice<'v, V, VR, A, AR>(
        &'v mut self,
        annotation: A,
        column: Column<Advice>,
        offset: usize,
        to: V,
    ) -> Result<AssignedCell<VR, F>, Error>
    where
        V: Fn() -> Value<VR> + 'v,
        for<'vr> Assigned<F>: From<&'vr VR>,
        A: Fn() -> AR,
        AR: Into<String>,
    {
        // Actually set the value
        let res = self.region.assign_advice(annotation, column, offset, &to);
        // Cache the value
        // Note that the `value_field` in `AssignedCell` might be `Value::unkonwn` if
        // the column has different phase than current one, so we call to `to`
        // again here to cache the value.
        if res.is_ok() {
            to().map(|f| {
                self.advice[column.index() - self.width_start][offset - self.height_start] =
                    Assigned::from(&f).evaluate();
            });
        }
        res
    }

    pub fn get_fixed(&self, _row_index: usize, _column_index: usize, _rotation: Rotation) -> F {
        unimplemented!("fixed column");
    }

    pub fn get_advice(&self, row_index: usize, column_index: usize, rotation: Rotation) -> F {
        self.advice[column_index - self.width_start]
            [(((row_index - self.height_start) as i32) + rotation.0) as usize]
    }

    pub fn challenges(&self) -> &Challenges<Value<F>> {
        self.challenges
    }

    // pub fn keccak_rlc(&self, le_bytes: &[u8]) -> Value<F> {
    //     self.challenges
    //         .keccak_input()
    //         .map(|r| rlc::value(le_bytes, r))
    // }

    pub fn code_hash(&self, n: U256) -> Word<Value<F>> {
        Word::from(n).into_value()
    }

    /// Constrains a cell to have a constant value.
    ///
    /// Returns an error if the cell is in a column where equality has not been
    /// enabled.
    pub fn constrain_constant<VR>(
        &mut self,
        cell: AssignedCell<F, F>,
        constant: VR,
    ) -> Result<(), Error>
    where
        VR: Into<Assigned<F>>,
    {
        self.region.constrain_constant(cell.cell(), constant.into())
    }
}

/// Decodes a field element from its byte representation in little endian order
pub(crate) mod from_bytes {
    use crate::util::Expr;
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
        debug_assert!(
            bytes.len() <= 32,
            "Too many bytes to compose an integer in field"
        );
        let mut value = 0.expr();
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value = value + byte.expr() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }

    pub(crate) fn value<F: Field>(bytes: &[u8]) -> F {
        debug_assert!(
            bytes.len() <= 32,
            "Too many bytes to compose an integer in field"
        );
        let mut value = F::ZERO;
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value += F::from(*byte as u64) * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

// /// Returns the random linear combination of the inputs.
// /// Encoding is done as follows: v_0 * R^0 + v_1 * R^1 + ...
pub(crate) mod rlc {
    use eth_types::Field;
    use std::ops::{Add, Mul};

    pub(crate) fn value<'a, F: Field, I>(values: I, randomness: F) -> F
    where
        I: IntoIterator<Item = &'a u8>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        let values = values
            .into_iter()
            .map(|v| F::from(*v as u64))
            .collect::<Vec<F>>();
        if !values.is_empty() {
            generic(values, randomness)
        } else {
            F::ZERO
        }
    }

    fn generic<V, I>(values: I, randomness: V) -> V
    where
        I: IntoIterator<Item = V>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
        V: Clone + Add<Output = V> + Mul<Output = V>,
    {
        let mut values = values.into_iter().rev();
        let init = values.next().expect("values should not be empty");

        values.fold(init, |acc, value| acc * randomness.clone() + value)
    }
}
