//! Ethereum and Evm types used to deserialize responses from web3 / geth.

pub mod keccak;
pub use keccak::{keccak256, Keccak};

pub use ethers_core::{
    abi::ethereum_types::{BigEndianHash, U512},
    types::{
        transaction::{eip2930::AccessList, response::Transaction},
        Address, Block, Bytes, Signature, H160, H256, H64, U256, U64,
    },
};

use ethers_core::types;
use halo2_proofs::halo2curves::{
    bn256::{Fq, Fr},
    ff::{Field as Halo2Field, FromUniformBytes, PrimeField},
};

/// Trait used to reduce verbosity with the declaration of the [`PrimeField`]
/// trait and its repr.
pub trait Field: Halo2Field + PrimeField<Repr = [u8; 32]> + FromUniformBytes<64> + Ord {
    /// Gets the lower 128 bits of this field element when expressed
    /// canonically.
    fn get_lower_128(&self) -> u128 {
        let bytes = self.to_repr();
        bytes[..16]
            .iter()
            .rev()
            .fold(0u128, |acc, value| acc * 256u128 + *value as u128)
    }
    /// Gets the lower 32 bits of this field element when expressed
    /// canonically.
    fn get_lower_32(&self) -> u32 {
        let bytes = self.to_repr();
        bytes[..4]
            .iter()
            .rev()
            .fold(0u32, |acc, value| acc * 256u32 + *value as u32)
    }
}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Frq to be used and consistent with the
// rest of the workspace.
impl Field for Fq {}

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}

/// Trait used to convert a type to a [`Word`].
pub trait ToWord {
    /// Convert the type to a [`Word`].
    fn to_word(&self) -> Word;
}

/// Trait used to convert a type to a [`Address`].
pub trait ToAddress {
    /// Convert the type to a [`Address`].
    fn to_address(&self) -> Address;
}

/// Trait uset do convert a scalar value to a 32 byte array in big endian.
pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

/// Trait used to convert a scalar value to a 32 byte array in little endian.
pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
}

/// Ethereum Word (256 bits).
pub type Word = U256;

impl ToBigEndian for U256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToLittleEndian for U256 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        bytes
    }
}

impl<F: Field> ToScalar<F> for U256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl ToAddress for U256 {
    fn to_address(&self) -> Address {
        Address::from_slice(&self.to_be_bytes()[12..])
    }
}

/// Ethereum Hash (256 bits).
pub type Hash = types::H256;

impl ToWord for Hash {
    fn to_word(&self) -> Word {
        Word::from(self.as_bytes())
    }
}

impl ToWord for Address {
    fn to_word(&self) -> Word {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        Word::from(bytes)
    }
}

impl ToWord for bool {
    fn to_word(&self) -> Word {
        if *self {
            Word::one()
        } else {
            Word::zero()
        }
    }
}

impl ToWord for u64 {
    fn to_word(&self) -> Word {
        Word::from(*self)
    }
}

impl ToWord for u128 {
    fn to_word(&self) -> Word {
        Word::from(*self)
    }
}

impl ToWord for usize {
    fn to_word(&self) -> Word {
        u64::try_from(*self)
            .expect("usize bigger than u64")
            .to_word()
    }
}

impl ToWord for i32 {
    fn to_word(&self) -> Word {
        let value = Word::from(self.unsigned_abs() as u64);
        if self.is_negative() {
            value.overflowing_neg().0
        } else {
            value
        }
    }
}

impl ToWord for U64 {
    fn to_word(&self) -> Word {
        self.as_u64().into()
    }
}

impl ToWord for Word {
    fn to_word(&self) -> Word {
        *self
    }
}

impl<F: Field> ToScalar<F> for Address {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        bytes.reverse();
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for bool {
    fn to_scalar(&self) -> Option<F> {
        self.to_word().to_scalar()
    }
}

impl<F: Field> ToScalar<F> for u64 {
    fn to_scalar(&self) -> Option<F> {
        Some(F::from(*self))
    }
}

impl<F: Field> ToScalar<F> for usize {
    fn to_scalar(&self) -> Option<F> {
        u64::try_from(*self).ok().map(F::from)
    }
}
