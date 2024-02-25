use super::Ed25519PublicKey;
use super::Ed25519Signature;
use super::Secp256k1PublicKey;
use super::Secp256k1Signature;
use super::Secp256r1PublicKey;
use super::Secp256r1Signature;

pub type WeightUnit = u8;
pub type ThresholdUnit = u16;
pub type BitmapUnit = u16;

#[cfg(feature = "serde")]
const MAX_COMMITTEE_SIZE: usize = 10;
// TODO validate sigs
// const MAX_BITMAP_VALUE: BitmapUnit = 0b1111111111;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum MultisigMemberPublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256k1(Secp256k1PublicKey),
    Secp256r1(Secp256r1PublicKey),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct MultisigMember {
    public_key: MultisigMemberPublicKey,
    weight: WeightUnit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct MultisigCommittee {
    /// A list of committee members and their corresponding weight.
    #[cfg_attr(
        test,
        proptest(
            strategy = "proptest::collection::vec(proptest::arbitrary::any::<MultisigMember>(), 0..10)"
        )
    )]
    members: Vec<MultisigMember>,
    /// If the total weight of the public keys corresponding to verified signatures is larger than threshold, the Multisig is verified.
    threshold: ThresholdUnit,
}

impl MultisigCommittee {
    pub fn members(&self) -> &[MultisigMember] {
        &self.members
    }

    pub fn threshold(&self) -> ThresholdUnit {
        self.threshold
    }
}

/// The struct that contains signatures and public keys necessary for authenticating a Multisig.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct MultisigAggregatedSignature {
    /// The plain signature encoded with signature scheme.
    #[cfg_attr(
        test,
        proptest(
            strategy = "proptest::collection::vec(proptest::arbitrary::any::<MultisigMemberSignature>(), 0..10)"
        )
    )]
    signatures: Vec<MultisigMemberSignature>,
    /// A bitmap that indicates the position of which public key the signature should be authenticated with.
    bitmap: BitmapUnit,
    /// Legacy encoding for the bitmap.
    // TODO remove the allow(dead_code) attr once the public interface has been fleshed out more
    #[cfg_attr(not(feature = "serde"), allow(dead_code))]
    //TODO implement a strategy for legacy bitmap
    #[cfg_attr(test, proptest(value = "None"))]
    legacy_bitmap: Option<roaring::RoaringBitmap>,
    /// The public key encoded with each public key with its signature scheme used along with the corresponding weight.
    committee: MultisigCommittee,
}

impl MultisigAggregatedSignature {
    pub fn signatures(&self) -> &[MultisigMemberSignature] {
        &self.signatures
    }

    pub fn bitmap(&self) -> BitmapUnit {
        self.bitmap
    }

    pub fn committee(&self) -> &MultisigCommittee {
        &self.committee
    }
}

impl PartialEq for MultisigAggregatedSignature {
    fn eq(&self, other: &Self) -> bool {
        // Skip comparing the legacy bitmap since we always convert to the new bitmap form
        self.bitmap == other.bitmap
            && self.signatures == other.signatures
            && self.committee == other.committee
    }
}

impl Eq for MultisigAggregatedSignature {}

/// Convert a roaring bitmap to plain bitmap.
#[cfg(feature = "serde")]
fn roaring_bitmap_to_u16(roaring: &roaring::RoaringBitmap) -> Result<BitmapUnit, &'static str> {
    let mut val = 0;
    for i in roaring.iter() {
        if i >= MAX_COMMITTEE_SIZE as u32 {
            return Err("invalid bitmap");
        }
        val |= 1 << i as u8;
    }
    Ok(val)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum MultisigMemberSignature {
    Ed25519(Ed25519Signature),
    Secp256k1(Secp256k1Signature),
    Secp256r1(Secp256r1Signature),
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use super::*;
    use crate::types::crypto::Base64Array33;
    use crate::types::crypto::Base64Array34;
    use crate::types::Ed25519PublicKey;
    use crate::types::Secp256k1PublicKey;
    use crate::types::Secp256r1PublicKey;
    use crate::types::SignatureScheme;
    use base64ct::{Base64, Encoding};
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serialize;
    use serde::Serializer;
    use serde_with::Bytes;
    use serde_with::DeserializeAs;
    use serde_with::SerializeAs;
    use std::borrow::Cow;

    /// Serializes a bitmap according to the roaring bitmap on-disk standard.
    /// <https://github.com/RoaringBitmap/RoaringFormatSpec>
    pub struct BinaryRoaringBitmap;

    impl SerializeAs<roaring::RoaringBitmap> for BinaryRoaringBitmap {
        fn serialize_as<S>(
            source: &roaring::RoaringBitmap,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = vec![];

            source
                .serialize_into(&mut bytes)
                .map_err(serde::ser::Error::custom)?;
            Bytes::serialize_as(&bytes, serializer)
        }
    }

    impl<'de> DeserializeAs<'de, roaring::RoaringBitmap> for BinaryRoaringBitmap {
        fn deserialize_as<D>(deserializer: D) -> Result<roaring::RoaringBitmap, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
            roaring::RoaringBitmap::deserialize_from(&bytes[..]).map_err(serde::de::Error::custom)
        }
    }

    pub struct Base64RoaringBitmap;

    impl SerializeAs<roaring::RoaringBitmap> for Base64RoaringBitmap {
        fn serialize_as<S>(
            source: &roaring::RoaringBitmap,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = vec![];

            source
                .serialize_into(&mut bytes)
                .map_err(serde::ser::Error::custom)?;
            let b64 = Base64::encode_string(&bytes);
            b64.serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, roaring::RoaringBitmap> for Base64RoaringBitmap {
        fn deserialize_as<D>(deserializer: D) -> Result<roaring::RoaringBitmap, D::Error>
        where
            D: Deserializer<'de>,
        {
            let b64: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
            let bytes = Base64::decode_vec(&b64).map_err(serde::de::Error::custom)?;
            roaring::RoaringBitmap::deserialize_from(&bytes[..]).map_err(serde::de::Error::custom)
        }
    }

    pub struct Base64MultisigMemberPublicKey;

    impl SerializeAs<MultisigMemberPublicKey> for Base64MultisigMemberPublicKey {
        fn serialize_as<S>(
            source: &MultisigMemberPublicKey,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match source {
                MultisigMemberPublicKey::Ed25519(public_key) => {
                    let mut buf = [0; 1 + Ed25519PublicKey::LENGTH];
                    buf[0] = SignatureScheme::Ed25519 as u8;
                    buf[1..].copy_from_slice(public_key.as_ref());
                    Base64Array33::serialize_as(&buf, serializer)
                }
                MultisigMemberPublicKey::Secp256k1(public_key) => {
                    let mut buf = [0; 1 + Secp256k1PublicKey::LENGTH];
                    buf[0] = SignatureScheme::Secp256k1 as u8;
                    buf[1..].copy_from_slice(public_key.as_ref());
                    Base64Array34::serialize_as(&buf, serializer)
                }
                MultisigMemberPublicKey::Secp256r1(public_key) => {
                    let mut buf = [0; 1 + Secp256r1PublicKey::LENGTH];
                    buf[0] = SignatureScheme::Secp256r1 as u8;
                    buf[1..].copy_from_slice(public_key.as_ref());
                    Base64Array34::serialize_as(&buf, serializer)
                }
            }
        }
    }

    impl<'de> DeserializeAs<'de, MultisigMemberPublicKey> for Base64MultisigMemberPublicKey {
        fn deserialize_as<D>(deserializer: D) -> Result<MultisigMemberPublicKey, D::Error>
        where
            D: Deserializer<'de>,
        {
            let b64: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
            let bytes = Base64::decode_vec(&b64).map_err(serde::de::Error::custom)?;
            let flag = SignatureScheme::from_byte(bytes[0]).map_err(serde::de::Error::custom)?;
            let public_key_bytes = &bytes[1..];
            match flag {
                SignatureScheme::Ed25519 => {
                    let public_key = Ed25519PublicKey::from_bytes(public_key_bytes)
                        .map_err(serde::de::Error::custom)?;
                    Ok(MultisigMemberPublicKey::Ed25519(public_key))
                }
                SignatureScheme::Secp256k1 => {
                    let public_key = Secp256k1PublicKey::from_bytes(public_key_bytes)
                        .map_err(serde::de::Error::custom)?;
                    Ok(MultisigMemberPublicKey::Secp256k1(public_key))
                }
                SignatureScheme::Secp256r1 => {
                    let public_key = Secp256r1PublicKey::from_bytes(public_key_bytes)
                        .map_err(serde::de::Error::custom)?;
                    Ok(MultisigMemberPublicKey::Secp256r1(public_key))
                }
                SignatureScheme::Multisig
                | SignatureScheme::BLS12381
                | SignatureScheme::ZkLoginAuthenticator => {
                    Err(serde::de::Error::custom("invalid public key type"))
                }
            }
        }
    }

    pub struct LegacyMultisigMember;

    impl SerializeAs<MultisigMember> for LegacyMultisigMember {
        fn serialize_as<S>(source: &MultisigMember, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            #[derive(serde_derive::Serialize)]
            struct LegacyMember<'a> {
                #[serde(with = "::serde_with::As::<Base64MultisigMemberPublicKey>")]
                public_key: &'a MultisigMemberPublicKey,
                weight: WeightUnit,
            }

            let legacy = LegacyMember {
                public_key: &source.public_key,
                weight: source.weight,
            };

            legacy.serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, MultisigMember> for LegacyMultisigMember {
        fn deserialize_as<D>(deserializer: D) -> Result<MultisigMember, D::Error>
        where
            D: Deserializer<'de>,
        {
            #[derive(serde_derive::Deserialize)]
            struct LegacyMember {
                #[serde(with = "::serde_with::As::<Base64MultisigMemberPublicKey>")]
                public_key: MultisigMemberPublicKey,
                weight: WeightUnit,
            }

            let legacy = LegacyMember::deserialize(deserializer)?;

            Ok(MultisigMember {
                public_key: legacy.public_key,
                weight: legacy.weight,
            })
        }
    }

    #[derive(serde_derive::Deserialize)]
    pub struct Multisig {
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        committee: MultisigCommittee,
    }

    #[derive(serde_derive::Serialize)]
    pub struct MultisigRef<'a> {
        signatures: &'a [MultisigMemberSignature],
        bitmap: BitmapUnit,
        committee: &'a MultisigCommittee,
    }

    #[derive(serde_derive::Deserialize)]
    pub struct LegacyMultisig {
        signatures: Vec<MultisigMemberSignature>,
        #[serde(with = "::serde_with::As::<BinaryRoaringBitmap>")]
        bitmap: roaring::RoaringBitmap,
        committee: LegacyMultisigCommittee,
    }

    #[derive(serde_derive::Serialize)]
    pub struct LegacyMultisigRef<'a> {
        signatures: &'a [MultisigMemberSignature],
        #[serde(with = "::serde_with::As::<BinaryRoaringBitmap>")]
        bitmap: &'a roaring::RoaringBitmap,
        committee: LegacyMultisigCommitteeRef<'a>,
    }

    #[derive(serde_derive::Deserialize)]
    struct LegacyMultisigCommittee {
        #[serde(with = "::serde_with::As::<Vec<LegacyMultisigMember>>")]
        members: Vec<MultisigMember>,
        threshold: ThresholdUnit,
    }

    #[derive(serde_derive::Serialize)]
    struct LegacyMultisigCommitteeRef<'a> {
        #[serde(with = "::serde_with::As::<&[LegacyMultisigMember]>")]
        members: &'a [MultisigMember],
        threshold: ThresholdUnit,
    }

    #[derive(serde_derive::Deserialize)]
    struct ReadableMultisigAggregatedSignature {
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        #[serde(default)]
        #[serde(with = "::serde_with::As::<Option<Base64RoaringBitmap>>")]
        legacy_bitmap: Option<roaring::RoaringBitmap>,
        committee: MultisigCommittee,
    }

    #[derive(serde_derive::Serialize)]
    struct ReadableMultisigAggregatedSignatureRef<'a> {
        signatures: &'a [MultisigMemberSignature],
        bitmap: BitmapUnit,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "::serde_with::As::<Option<Base64RoaringBitmap>>")]
        legacy_bitmap: &'a Option<roaring::RoaringBitmap>,
        committee: &'a MultisigCommittee,
    }

    impl Serialize for MultisigAggregatedSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = ReadableMultisigAggregatedSignatureRef {
                    signatures: &self.signatures,
                    bitmap: self.bitmap,
                    legacy_bitmap: &self.legacy_bitmap,
                    committee: &self.committee,
                };
                readable.serialize(serializer)
            } else {
                let mut buf = Vec::new();
                buf.push(SignatureScheme::Multisig as u8);

                if let Some(bitmap) = &self.legacy_bitmap {
                    let legacy = LegacyMultisigRef {
                        signatures: &self.signatures,
                        bitmap,
                        committee: LegacyMultisigCommitteeRef {
                            members: &self.committee.members,
                            threshold: self.committee.threshold,
                        },
                    };

                    bcs::serialize_into(&mut buf, &legacy).expect("serialization cannot fail");
                } else {
                    let multisig = MultisigRef {
                        signatures: &self.signatures,
                        bitmap: self.bitmap,
                        committee: &self.committee,
                    };
                    bcs::serialize_into(&mut buf, &multisig).expect("serialization cannot fail");
                }
                serializer.serialize_bytes(&buf)
            }
        }
    }

    impl<'de> Deserialize<'de> for MultisigAggregatedSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadableMultisigAggregatedSignature::deserialize(deserializer)?;
                Ok(Self {
                    signatures: readable.signatures,
                    bitmap: readable.bitmap,
                    legacy_bitmap: readable.legacy_bitmap,
                    committee: readable.committee,
                })
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_serialized_bytes(bytes)
            }
        }
    }

    impl MultisigAggregatedSignature {
        pub(crate) fn from_serialized_bytes<T: AsRef<[u8]>, E: serde::de::Error>(
            bytes: T,
        ) -> Result<Self, E> {
            let bytes = bytes.as_ref();
            let flag = SignatureScheme::from_byte(bytes[0]).map_err(serde::de::Error::custom)?;
            if flag != SignatureScheme::Multisig {
                return Err(serde::de::Error::custom("invalid multisig flag"));
            }
            let bcs_bytes = &bytes[1..];

            // Unfortunately we have no information in the serialized form of a Multisig to be
            // able to determine if its a Legacy format or the new standard format so we just
            // need to try each.
            //
            // We'll start with the newer format as that should be more prevalent.
            if let Ok(multisig) = bcs::from_bytes::<Multisig>(bcs_bytes) {
                Ok(Self {
                    signatures: multisig.signatures,
                    bitmap: multisig.bitmap,
                    legacy_bitmap: None,
                    committee: multisig.committee,
                })
            } else if let Ok(legacy) = bcs::from_bytes::<LegacyMultisig>(bcs_bytes) {
                Ok(Self {
                    signatures: legacy.signatures,
                    bitmap: roaring_bitmap_to_u16(&legacy.bitmap)
                        .map_err(serde::de::Error::custom)?,
                    legacy_bitmap: Some(legacy.bitmap),
                    committee: MultisigCommittee {
                        members: legacy.committee.members,
                        threshold: legacy.committee.threshold,
                    },
                })
            } else {
                Err(serde::de::Error::custom("invalid multisig"))
            }
        }
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    enum MemberPublicKey {
        Ed25519(Ed25519PublicKey),
        Secp256k1(Secp256k1PublicKey),
        Secp256r1(Secp256r1PublicKey),
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    enum ReadableMemberPublicKey {
        Ed25519 { public_key: Ed25519PublicKey },
        Secp256k1 { public_key: Secp256k1PublicKey },
        Secp256r1 { public_key: Secp256r1PublicKey },
    }

    impl Serialize for MultisigMemberPublicKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    MultisigMemberPublicKey::Ed25519(public_key) => {
                        ReadableMemberPublicKey::Ed25519 {
                            public_key: *public_key,
                        }
                    }
                    MultisigMemberPublicKey::Secp256k1(public_key) => {
                        ReadableMemberPublicKey::Secp256k1 {
                            public_key: *public_key,
                        }
                    }
                    MultisigMemberPublicKey::Secp256r1(public_key) => {
                        ReadableMemberPublicKey::Secp256r1 {
                            public_key: *public_key,
                        }
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    MultisigMemberPublicKey::Ed25519(public_key) => {
                        MemberPublicKey::Ed25519(*public_key)
                    }
                    MultisigMemberPublicKey::Secp256k1(public_key) => {
                        MemberPublicKey::Secp256k1(*public_key)
                    }
                    MultisigMemberPublicKey::Secp256r1(public_key) => {
                        MemberPublicKey::Secp256r1(*public_key)
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for MultisigMemberPublicKey {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadableMemberPublicKey::deserialize(deserializer)?;
                Ok(match readable {
                    ReadableMemberPublicKey::Ed25519 { public_key } => Self::Ed25519(public_key),
                    ReadableMemberPublicKey::Secp256k1 { public_key } => {
                        Self::Secp256k1(public_key)
                    }
                    ReadableMemberPublicKey::Secp256r1 { public_key } => {
                        Self::Secp256r1(public_key)
                    }
                })
            } else {
                let binary = MemberPublicKey::deserialize(deserializer)?;
                Ok(match binary {
                    MemberPublicKey::Ed25519(public_key) => Self::Ed25519(public_key),
                    MemberPublicKey::Secp256k1(public_key) => Self::Secp256k1(public_key),
                    MemberPublicKey::Secp256r1(public_key) => Self::Secp256r1(public_key),
                })
            }
        }
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    enum MemberSignature {
        Ed25519(Ed25519Signature),
        Secp256k1(Secp256k1Signature),
        Secp256r1(Secp256r1Signature),
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    enum ReadableMemberSignature {
        Ed25519 { signature: Ed25519Signature },
        Secp256k1 { signature: Secp256k1Signature },
        Secp256r1 { signature: Secp256r1Signature },
    }

    impl Serialize for MultisigMemberSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    MultisigMemberSignature::Ed25519(signature) => {
                        ReadableMemberSignature::Ed25519 {
                            signature: *signature,
                        }
                    }
                    MultisigMemberSignature::Secp256k1(signature) => {
                        ReadableMemberSignature::Secp256k1 {
                            signature: *signature,
                        }
                    }
                    MultisigMemberSignature::Secp256r1(signature) => {
                        ReadableMemberSignature::Secp256r1 {
                            signature: *signature,
                        }
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    MultisigMemberSignature::Ed25519(signature) => {
                        MemberSignature::Ed25519(*signature)
                    }
                    MultisigMemberSignature::Secp256k1(signature) => {
                        MemberSignature::Secp256k1(*signature)
                    }
                    MultisigMemberSignature::Secp256r1(signature) => {
                        MemberSignature::Secp256r1(*signature)
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for MultisigMemberSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadableMemberSignature::deserialize(deserializer)?;
                Ok(match readable {
                    ReadableMemberSignature::Ed25519 { signature } => Self::Ed25519(signature),
                    ReadableMemberSignature::Secp256k1 { signature } => Self::Secp256k1(signature),
                    ReadableMemberSignature::Secp256r1 { signature } => Self::Secp256r1(signature),
                })
            } else {
                let binary = MemberSignature::deserialize(deserializer)?;
                Ok(match binary {
                    MemberSignature::Ed25519(signature) => Self::Ed25519(signature),
                    MemberSignature::Secp256k1(signature) => Self::Secp256k1(signature),
                    MemberSignature::Secp256r1(signature) => Self::Secp256r1(signature),
                })
            }
        }
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    struct Member {
        public_key: MultisigMemberPublicKey,
        weight: WeightUnit,
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    struct ReadableMember {
        #[cfg_attr(feature = "serde", serde(flatten))]
        public_key: MultisigMemberPublicKey,
        weight: WeightUnit,
    }

    impl Serialize for MultisigMember {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = ReadableMember {
                    public_key: self.public_key.clone(),
                    weight: self.weight,
                };
                readable.serialize(serializer)
            } else {
                let binary = Member {
                    public_key: self.public_key.clone(),
                    weight: self.weight,
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for MultisigMember {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadableMember::deserialize(deserializer)?;
                Ok(Self {
                    public_key: readable.public_key,
                    weight: readable.weight,
                })
            } else {
                let binary = Member::deserialize(deserializer)?;
                Ok(Self {
                    public_key: binary.public_key,
                    weight: binary.weight,
                })
            }
        }
    }
}
