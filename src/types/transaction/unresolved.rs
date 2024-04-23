use crate::types::{object::Version, Address, ObjectDigest, ObjectId};

use super::{Command, TransactionExpiration};



// Sponsored transaction flow:
// 1. user constructs unresolved transaction
// 2. user resolved everything execpt gas owner and objects
// 3. sends unresolved txn to Sponsor
// 4. sponsor selects gas objects and can reset budget if needed sends it back to user
// 5. user signs txn and sends to sponsor
// 6. sponser signs and sends txn to be executed

// A potentially Unresolved user transaction
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
pub struct UnresolvedTransaction {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub ptb: UnresolvedProgrammableTransaction,
    pub sender: Address,
    pub gas_payment: Option<UnresolvedGasPayment>,
    // maybe allow asking for expiration in x epochs from now
    pub expiration: Option<TransactionExpiration>,
}

#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
pub struct UnresolvedProgrammableTransaction {
    pub inputs: Vec<UnresolvedInputArgument>,
    pub commands: Vec<Command>, // Make this Unresolved so that we can not specify type arguments
}

#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
pub struct UnresolvedGasPayment {
    // If user dones't have gas objects we don't want this to fail
    // We can add enum or boolean field to express that we don't want these to be resolved
    
    pub objects: Option<Vec<UnresolvedObjectReference>>, // in order to do gas selection you'd need
                                                         // an owner index on FN (graphql/indexer
                                                         // does have this)
    pub owner: Option<Address>, // Default to sender and their objects
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::_serde::OptionReadableDisplay")
    )]
    pub price: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::_serde::OptionReadableDisplay")
    )]
    pub budget: Option<u64>,
}

#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
pub struct UnresolvedObjectReference {
    pub object_id: ObjectId,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::_serde::OptionReadableDisplay")
    )]
    pub version: Option<Version>,
    pub digest: Option<ObjectDigest>,
}

#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
pub enum UnresolvedInputArgument {
    // contains no structs or objects
    Pure {
        #[cfg_attr(
            feature = "serde",
            serde(with = "::serde_with::As::<::serde_with::Bytes>")
        )]
        value: Vec<u8>,
        // maybe type here that is optional? type_
    },
    // Desire to pass in scalar value
    // number u64 or u128 need to be strings
    // string
    // Vec
    // option
    // bools
    UnserializedPure {
        value: ??? or Enum
        type_: ???
    }
    // A Move object, either immutable, or owned mutable.
    ImmutableOrOwned(UnresolvedObjectReference),
    // A Move object that's shared.
    // SharedObject::mutable controls whether caller asks for a mutable reference to shared object.
    Shared {
        object_id: ObjectId,
        #[cfg_attr(
            feature = "serde",
            serde(with = "crate::_serde::OptionReadableDisplay")
        )]
        initial_shared_version: Option<u64>,
        mutable: Option<bool>,
    },
    // A Move object that can be received in this transaction.
    Receiving(UnresolvedObjectReference), // We can look at the type definition of a move call and
                                          // it has to have the type "0x2::transfer::Receiving<T>"
    // Yeah sure maybe we can do this?
    Object(ObjectId),
}

// {
//    type = owned
//     object_id =
//     Version
//     digest
// }
//
// {
//    type = shared
//    object_id =
//    initial_shared_version
//    mutable
// }
//
// {
//    type = recieving
//    object_id =
//    version
//    digest
// }
