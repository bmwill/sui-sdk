use super::Address;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct ObjectId(Address);

impl ObjectId {
    pub const LENGTH: usize = Address::LENGTH;
    pub const ZERO: Self = Self(Address::ZERO);
}

impl From<Address> for ObjectId {
    fn from(value: Address) -> Self {
        Self(value)
    }
}

impl From<ObjectId> for Vec<u8> {
    fn from(value: ObjectId) -> Self {
        value.0.into()
    }
}
