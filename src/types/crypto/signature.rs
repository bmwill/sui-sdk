use super::Ed25519PublicKey;
use super::Ed25519Signature;
use super::MultisigAggregatedSignature;
use super::PasskeyAuthenticator;
use super::Secp256k1PublicKey;
use super::Secp256k1Signature;
use super::Secp256r1PublicKey;
use super::Secp256r1Signature;
use super::ZkLoginAuthenticator;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "scheme", rename_all = "lowercase")
)]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
pub enum SimpleSignature {
    Ed25519 {
        signature: Ed25519Signature,
        public_key: Ed25519PublicKey,
    },
    Secp256k1 {
        signature: Secp256k1Signature,
        public_key: Secp256k1PublicKey,
    },
    Secp256r1 {
        signature: Secp256r1Signature,
        public_key: Secp256r1PublicKey,
    },
}

impl SimpleSignature {
    pub fn scheme(&self) -> SignatureScheme {
        match self {
            SimpleSignature::Ed25519 { .. } => SignatureScheme::Ed25519,
            SimpleSignature::Secp256k1 { .. } => SignatureScheme::Secp256k1,
            SimpleSignature::Secp256r1 { .. } => SignatureScheme::Secp256r1,
        }
    }
}

impl SimpleSignature {
    #[cfg(feature = "serde")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
    fn from_serialized_bytes<T: AsRef<[u8]>, E: serde::de::Error>(bytes: T) -> Result<Self, E> {
        let bytes = bytes.as_ref();
        let flag = SignatureScheme::from_byte(
            *bytes
                .first()
                .ok_or_else(|| serde::de::Error::custom("missing signature scheme falg"))?,
        )
        .map_err(serde::de::Error::custom)?;
        match flag {
            SignatureScheme::Ed25519 => {
                let expected_length = 1 + Ed25519Signature::LENGTH + Ed25519PublicKey::LENGTH;

                if bytes.len() != expected_length {
                    return Err(serde::de::Error::custom("invalid ed25519 signature"));
                }

                let mut signature = [0; Ed25519Signature::LENGTH];
                signature.copy_from_slice(&bytes[1..(1 + Ed25519Signature::LENGTH)]);

                let mut public_key = [0; Ed25519PublicKey::LENGTH];
                public_key.copy_from_slice(&bytes[(1 + Ed25519Signature::LENGTH)..]);

                Ok(SimpleSignature::Ed25519 {
                    signature: Ed25519Signature::new(signature),
                    public_key: Ed25519PublicKey::new(public_key),
                })
            }
            SignatureScheme::Secp256k1 => {
                let expected_length = 1 + Secp256k1Signature::LENGTH + Secp256k1PublicKey::LENGTH;

                if bytes.len() != expected_length {
                    return Err(serde::de::Error::custom("invalid secp25k1 signature"));
                }

                let mut signature = [0; Secp256k1Signature::LENGTH];
                signature.copy_from_slice(&bytes[1..(1 + Secp256k1Signature::LENGTH)]);

                let mut public_key = [0; Secp256k1PublicKey::LENGTH];
                public_key.copy_from_slice(&bytes[(1 + Secp256k1Signature::LENGTH)..]);

                Ok(SimpleSignature::Secp256k1 {
                    signature: Secp256k1Signature::new(signature),
                    public_key: Secp256k1PublicKey::new(public_key),
                })
            }
            SignatureScheme::Secp256r1 => {
                let expected_length = 1 + Secp256r1Signature::LENGTH + Secp256r1PublicKey::LENGTH;

                if bytes.len() != expected_length {
                    return Err(serde::de::Error::custom("invalid secp25r1 signature"));
                }

                let mut signature = [0; Secp256r1Signature::LENGTH];
                signature.copy_from_slice(&bytes[1..(1 + Secp256r1Signature::LENGTH)]);

                let mut public_key = [0; Secp256r1PublicKey::LENGTH];
                public_key.copy_from_slice(&bytes[(1 + Secp256r1Signature::LENGTH)..]);

                Ok(SimpleSignature::Secp256r1 {
                    signature: Secp256r1Signature::new(signature),
                    public_key: Secp256r1PublicKey::new(public_key),
                })
            }
            SignatureScheme::Multisig
            | SignatureScheme::Bls12381
            | SignatureScheme::ZkLogin
            | SignatureScheme::Passkey => Err(serde::de::Error::custom("invalid signature scheme")),
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
impl serde::Serialize for SimpleSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde_derive::Serialize)]
        #[serde(tag = "scheme")]
        #[serde(rename_all = "lowercase")]
        enum Sig<'a> {
            Ed25519 {
                signature: &'a Ed25519Signature,
                public_key: &'a Ed25519PublicKey,
            },
            Secp256k1 {
                signature: &'a Secp256k1Signature,
                public_key: &'a Secp256k1PublicKey,
            },
            Secp256r1 {
                signature: &'a Secp256r1Signature,
                public_key: &'a Secp256r1PublicKey,
            },
        }

        if serializer.is_human_readable() {
            let sig = match self {
                SimpleSignature::Ed25519 {
                    signature,
                    public_key,
                } => Sig::Ed25519 {
                    signature,
                    public_key,
                },
                SimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                } => Sig::Secp256k1 {
                    signature,
                    public_key,
                },
                SimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                } => Sig::Secp256r1 {
                    signature,
                    public_key,
                },
            };

            sig.serialize(serializer)
        } else {
            match self {
                SimpleSignature::Ed25519 {
                    signature,
                    public_key,
                } => {
                    let mut buf = [0; 1 + Ed25519Signature::LENGTH + Ed25519PublicKey::LENGTH];
                    buf[0] = SignatureScheme::Ed25519 as u8;
                    buf[1..(1 + Ed25519Signature::LENGTH)].copy_from_slice(signature.as_ref());
                    buf[(1 + Ed25519Signature::LENGTH)..].copy_from_slice(public_key.as_ref());

                    serializer.serialize_bytes(&buf)
                }
                SimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                } => {
                    let mut buf = [0; 1 + Secp256k1Signature::LENGTH + Secp256k1PublicKey::LENGTH];
                    buf[0] = SignatureScheme::Secp256k1 as u8;
                    buf[1..(1 + Secp256k1Signature::LENGTH)].copy_from_slice(signature.as_ref());
                    buf[(1 + Secp256k1Signature::LENGTH)..].copy_from_slice(public_key.as_ref());

                    serializer.serialize_bytes(&buf)
                }
                SimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                } => {
                    let mut buf = [0; 1 + Secp256r1Signature::LENGTH + Secp256r1PublicKey::LENGTH];
                    buf[0] = SignatureScheme::Secp256r1 as u8;
                    buf[1..(1 + Secp256r1Signature::LENGTH)].copy_from_slice(signature.as_ref());
                    buf[(1 + Secp256r1Signature::LENGTH)..].copy_from_slice(public_key.as_ref());

                    serializer.serialize_bytes(&buf)
                }
            }
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for SimpleSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde_derive::Deserialize)]
        #[serde(tag = "scheme")]
        #[serde(rename_all = "lowercase")]
        enum Sig {
            Ed25519 {
                signature: Ed25519Signature,
                public_key: Ed25519PublicKey,
            },
            Secp256k1 {
                signature: Secp256k1Signature,
                public_key: Secp256k1PublicKey,
            },
            Secp256r1 {
                signature: Secp256r1Signature,
                public_key: Secp256r1PublicKey,
            },
        }

        if deserializer.is_human_readable() {
            let sig = Sig::deserialize(deserializer)?;
            Ok(match sig {
                Sig::Ed25519 {
                    signature,
                    public_key,
                } => SimpleSignature::Ed25519 {
                    signature,
                    public_key,
                },
                Sig::Secp256k1 {
                    signature,
                    public_key,
                } => SimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                },
                Sig::Secp256r1 {
                    signature,
                    public_key,
                } => SimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                },
            })
        } else {
            let bytes: std::borrow::Cow<'de, [u8]> = std::borrow::Cow::deserialize(deserializer)?;
            Self::from_serialized_bytes(bytes)
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
#[repr(u8)]
pub enum SignatureScheme {
    Ed25519 = 0x00,
    Secp256k1 = 0x01,
    Secp256r1 = 0x02,
    Multisig = 0x03,
    Bls12381 = 0x04, // This is currently not supported for user addresses
    ZkLogin = 0x05,
    Passkey = 0x06,
}

impl SignatureScheme {
    pub fn name(self) -> &'static str {
        match self {
            SignatureScheme::Ed25519 => "ed25519",
            SignatureScheme::Secp256k1 => "secp256k1",
            SignatureScheme::Secp256r1 => "secp256r1",
            SignatureScheme::Multisig => "multisig",
            SignatureScheme::Bls12381 => "bls12381",
            SignatureScheme::ZkLogin => "zklogin",
            SignatureScheme::Passkey => "passkey",
        }
    }

    pub fn from_byte(flag: u8) -> Result<Self, InvalidSignatureScheme> {
        match flag {
            0x00 => Ok(Self::Ed25519),
            0x01 => Ok(Self::Secp256k1),
            0x02 => Ok(Self::Secp256r1),
            0x03 => Ok(Self::Multisig),
            0x04 => Ok(Self::Bls12381),
            0x05 => Ok(Self::ZkLogin),
            0x06 => Ok(Self::Passkey),
            invalid => Err(InvalidSignatureScheme(invalid)),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Ed25519PublicKey {
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}

impl Secp256k1PublicKey {
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }
}

impl Secp256r1PublicKey {
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256r1
    }
}

impl super::ZkLoginPublicIdentifier {
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ZkLogin
    }
}

impl super::PasskeyPublicKey {
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Passkey
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct InvalidSignatureScheme(u8);

impl std::fmt::Display for InvalidSignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid signature scheme: {:02x}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
pub enum UserSignature {
    Simple(SimpleSignature),
    Multisig(MultisigAggregatedSignature),
    ZkLogin(Box<ZkLoginAuthenticator>),
    Passkey(PasskeyAuthenticator),
}

impl UserSignature {
    pub fn scheme(&self) -> SignatureScheme {
        match self {
            UserSignature::Simple(simple) => simple.scheme(),
            UserSignature::Multisig(_) => SignatureScheme::Multisig,
            UserSignature::ZkLogin(_) => SignatureScheme::ZkLogin,
            UserSignature::Passkey(_) => SignatureScheme::Passkey,
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use super::*;

    #[derive(serde_derive::Serialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    enum ReadableUserSignatureRef<'a> {
        Ed25519 {
            signature: &'a Ed25519Signature,
            public_key: &'a Ed25519PublicKey,
        },
        Secp256k1 {
            signature: &'a Secp256k1Signature,
            public_key: &'a Secp256k1PublicKey,
        },
        Secp256r1 {
            signature: &'a Secp256r1Signature,
            public_key: &'a Secp256r1PublicKey,
        },
        Multisig(&'a MultisigAggregatedSignature),
        ZkLogin(&'a ZkLoginAuthenticator),
        Passkey(&'a PasskeyAuthenticator),
    }

    #[derive(serde_derive::Deserialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "UserSignature")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    enum ReadableUserSignature {
        Ed25519 {
            signature: Ed25519Signature,
            public_key: Ed25519PublicKey,
        },
        Secp256k1 {
            signature: Secp256k1Signature,
            public_key: Secp256k1PublicKey,
        },
        Secp256r1 {
            signature: Secp256r1Signature,
            public_key: Secp256r1PublicKey,
        },
        Multisig(MultisigAggregatedSignature),
        ZkLogin(Box<ZkLoginAuthenticator>),
        Passkey(PasskeyAuthenticator),
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for UserSignature {
        fn schema_name() -> String {
            ReadableUserSignature::schema_name()
        }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            ReadableUserSignature::json_schema(gen)
        }
    }

    impl serde::Serialize for UserSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    UserSignature::Simple(SimpleSignature::Ed25519 {
                        signature,
                        public_key,
                    }) => ReadableUserSignatureRef::Ed25519 {
                        signature,
                        public_key,
                    },
                    UserSignature::Simple(SimpleSignature::Secp256k1 {
                        signature,
                        public_key,
                    }) => ReadableUserSignatureRef::Secp256k1 {
                        signature,
                        public_key,
                    },
                    UserSignature::Simple(SimpleSignature::Secp256r1 {
                        signature,
                        public_key,
                    }) => ReadableUserSignatureRef::Secp256r1 {
                        signature,
                        public_key,
                    },
                    UserSignature::Multisig(multisig) => {
                        ReadableUserSignatureRef::Multisig(multisig)
                    }
                    UserSignature::ZkLogin(zklogin) => ReadableUserSignatureRef::ZkLogin(zklogin),
                    UserSignature::Passkey(passkey) => ReadableUserSignatureRef::Passkey(passkey),
                };
                readable.serialize(serializer)
            } else {
                match self {
                    UserSignature::Simple(simple) => simple.serialize(serializer),
                    UserSignature::Multisig(multisig) => multisig.serialize(serializer),
                    UserSignature::ZkLogin(zklogin) => zklogin.serialize(serializer),
                    UserSignature::Passkey(passkey) => passkey.serialize(serializer),
                }
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for UserSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadableUserSignature::deserialize(deserializer)?;
                Ok(match readable {
                    ReadableUserSignature::Ed25519 {
                        signature,
                        public_key,
                    } => Self::Simple(SimpleSignature::Ed25519 {
                        signature,
                        public_key,
                    }),
                    ReadableUserSignature::Secp256k1 {
                        signature,
                        public_key,
                    } => Self::Simple(SimpleSignature::Secp256k1 {
                        signature,
                        public_key,
                    }),
                    ReadableUserSignature::Secp256r1 {
                        signature,
                        public_key,
                    } => Self::Simple(SimpleSignature::Secp256r1 {
                        signature,
                        public_key,
                    }),
                    ReadableUserSignature::Multisig(multisig) => Self::Multisig(multisig),
                    ReadableUserSignature::ZkLogin(zklogin) => Self::ZkLogin(zklogin),
                    ReadableUserSignature::Passkey(passkey) => Self::Passkey(passkey),
                })
            } else {
                use serde_with::DeserializeAs;

                let bytes: std::borrow::Cow<'de, [u8]> =
                    serde_with::Bytes::deserialize_as(deserializer)?;
                let flag =
                    SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
                        serde::de::Error::custom("missing signature scheme falg")
                    })?)
                    .map_err(serde::de::Error::custom)?;
                match flag {
                    SignatureScheme::Ed25519
                    | SignatureScheme::Secp256k1
                    | SignatureScheme::Secp256r1 => {
                        let simple = SimpleSignature::from_serialized_bytes(bytes)?;
                        Ok(Self::Simple(simple))
                    }
                    SignatureScheme::Multisig => {
                        let multisig = MultisigAggregatedSignature::from_serialized_bytes(bytes)?;
                        Ok(Self::Multisig(multisig))
                    }
                    SignatureScheme::Bls12381 => Err(serde::de::Error::custom(
                        "bls not supported for user signatures",
                    )),
                    SignatureScheme::ZkLogin => {
                        let zklogin = ZkLoginAuthenticator::from_serialized_bytes(bytes)?;
                        Ok(Self::ZkLogin(Box::new(zklogin)))
                    }
                    SignatureScheme::Passkey => {
                        let passkey = PasskeyAuthenticator::from_serialized_bytes(bytes)?;
                        Ok(Self::Passkey(passkey))
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use base64ct::Base64;
        use base64ct::Encoding;
        use test_strategy::proptest;

        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test as test;

        #[proptest]
        fn roundtrip_signature_scheme(scheme: SignatureScheme) {
            assert_eq!(Ok(scheme), SignatureScheme::from_byte(scheme.to_u8()));
        }

        #[test]
        fn simple_fixtures() {
            const FIXTURES: &[(SignatureScheme, &str)]  = &[
                (SignatureScheme::Ed25519, "YQDaeO4w2ULMy5eqHBzP0oalr1YhDX/9uJS9MntKnW3d55q4aqZYYnoEloaBmXKc6FoD5bTwONdwS9CwdMQGhIcPDX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U="),
                (SignatureScheme::Secp256k1, "YgErcT6WUSQXGD1DaIwls5rWq648akDMlvL41ugUUhyIPWnqURl+daQLG+ILNemARKHYVNOikKJJ8jqu+HzlRa5rAg4XzVk55GsZZkGWjNdZkQuiV34n+nP944dtub7FvOsr"),
                (SignatureScheme::Secp256r1, "YgLp1p4K9dSQTt2AeR05yK1MkXmtLm6Sieb9yfkpW1gOBiqnO9ZKZiWUrLJQav2Mxw64zM37g3IVdsB/To6qfl8IA0f7ryPwOKvEwwiicRF6Kkz/rt28X/gcdRe8bHSn7bQw"),
            ];

            for (scheme, fixture) in FIXTURES {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
                assert_eq!(*scheme, sig.scheme());
                let bytes = bcs::to_bytes(&sig).unwrap();
                assert_eq!(bcs, bytes);

                let json = serde_json::to_string_pretty(&sig).unwrap();
                println!("{json}");
                assert_eq!(sig, serde_json::from_str(&json).unwrap());
            }
        }

        #[test]
        fn legacy_multisig_fixtures() {
            const FIXTURE1: &str = "rgIDAgAnwUSyrALP8m0eEPZE6aPggBELk72n1u3LU+i4nx5kqzhahcICbskEYzHJrbarvFr/RQITgDMoorqpDhN8dgsKATyrN3CD8g37D60dYiGW6sOBqIcf3E1mdMsKvX2pbOZsYQv8VNL+2Jz3vnMXcwEZF32PplKjcnmyUGRhV11M7n4UOjAAAAEAAAAAAAEAEAAAAAAAAQADLEFBMTlxeldNamEycVR2b0FTYWRiQjBObFZiRUtOb0ladTJnUGNGY1RTZGQxATBBUUlPRjgxWk9lUnJHV1pCbG96WFdaRUxvbGQrSi9wei9lT0hiYm0reGJ6ckt3PT0BMEFnTkgrNjhqOERpcnhNTUlvbkVSZWlwTS82N2R2Ri80SEhVWHZHeDBwKzIwTUE9PQECAA==";

            const FIXTURE2: &str = "8QIDAwDYAAra4KQGp2Oq1TCOgWfH8IxC4UA5wJB/NqOcNmMh54Y5d5pnVQfTlqgq4J17a8+W+y3+jk9h4YMB9LzPDYcLAaJJBH+WLPfPaQ7T3Cv8nqpZ1TbPrT8E61FrSgeIbN4OTJeijjguv1pd3ImvTeo4AMYZczf5OH6+5yBaur7R6YACiooT5J36agjUk0TpVcTKMGwykIwD7NBkZ0gbinHxuVJwdi1tSbqhMpqvNgP+CFO6F7FSTe+xiHh0MDOKyYQItxY6MAAAAQAAAAAAAgAQAAAAAAABAAIAAyxBQTE5cXpXTWphMnFUdm9BU2FkYkIwTmxWYkVLTm9JWnUyZ1BjRmNUU2RkMQEwQVFJT0Y4MVpPZVJyR1daQmxvelhXWkVMb2xkK0ovcHovZU9IYmJtK3hienJLdz09ATBBZ05IKzY4ajhEaXJ4TU1Jb25FUmVpcE0vNjdkdkYvNEhIVVh2R3gwcCsyME1BPT0BAgA=";

            for fixture in [FIXTURE1, FIXTURE2] {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
                assert_eq!(SignatureScheme::Multisig, sig.scheme());
                let bytes = bcs::to_bytes(&sig).unwrap();
                assert_eq!(bcs, bytes);

                let json = serde_json::to_string_pretty(&sig).unwrap();
                println!("{json}");
                assert_eq!(sig, serde_json::from_str(&json).unwrap());
            }
        }

        #[test]
        fn multisig_fixtures() {
            const FIXTURE1: &str = "sgIDAwCTLgVngjC4yeuvpAGKVkgcvIKVFUJnL1r6oFZScQVE5DNIz6kfxAGDRcVUczE9CUb7/sN/EuFJ8ot86Sdb8pAFASoQ91stRHXdW5dLy0BQ6v+7XWptawy2ItMyPk508p+PHdtZcm2aKl3lZGIvXe6MPY73E+1Hakv/xJbTYsw5SPMC5dx3gBwxds2GV12c7VUSqkyXamliSF1W/QBMufqrlmdIOZ1ox9gbsvIPtXYahfvKm8ozA7rsZWwRv8atsnyfYgcAAwANfas1jI2tqk76AEmnWwdDZVWxCjaCGbtoD3BXE0nXdQEBAg4XzVk55GsZZkGWjNdZkQuiV34n+nP944dtub7FvOsrAQIDR/uvI/A4q8TDCKJxEXoqTP+u3bxf+Bx1F7xsdKfttDABAgA=";

            const FIXTURE2: &str = "8QEDAgBMW4Oq7XMjO5c6HLgTBJrWDZsCEcZF2EPOf68fdf1aY3e3pvA3cmk0tjMmXFB9+A6J2NohCpTFb/CsXEBjtCcMAfraaMMOMzG815145jlrY44Rbp0d1JQJOJ3hjgEe2xVBFP3QR94IVZk6ssyYxsecpBA+re5eqVRacvZGSobNPkMDAAMADX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13UBAQIOF81ZOeRrGWZBlozXWZELold+J/pz/eOHbbm+xbzrKwECA0f7ryPwOKvEwwiicRF6Kkz/rt28X/gcdRe8bHSn7bQwAQIA";

            for fixture in [FIXTURE1, FIXTURE2] {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
                assert_eq!(SignatureScheme::Multisig, sig.scheme());
                let bytes = bcs::to_bytes(&sig).unwrap();
                assert_eq!(bcs, bytes);

                let json = serde_json::to_string_pretty(&sig).unwrap();
                println!("{json}");
                assert_eq!(sig, serde_json::from_str(&json).unwrap());
            }
        }

        #[test]
        fn mutisig_with_zklogin() {
            const FIXTURE: &str = "xwgDAQOWBwUDTDYyNzM5OTI5NDQyODI2NTYyNDE2NDMyNDk5Njc1NDY0MzY0MTU2ODM1MzgzMzAwNzMzMDkwMzgyOTUwOTAwMjA0MzcwMzI3MzQ0MTdNMTM5MjUxMzE5MTUzODM4NDMwOTkzODU1NTU2MjYyNzIwMzI5NjE5MjM3MjY1ODAyMjY2OTcwMTUzMTkxOTcxMzIxODkxMTg2MDUyNTcBMQMCTDc3MDQwMDc2MTQxMjAyNDQ0MjgyMDMyMzQwMzI3NzQ2ODkwODEwNzg2Mzg4NjkzMTcyNDM1NTEyNTMwMTA3MjYzMzg1MTA0MzYxMjdMNDczMzY5MTU2NjAwODE5MTIwNDAxMjcwNTc5OTA2MjI3NTk2MjY0NzMwMTUyNDU3MDIxMjM0MzczMjc1MTE3MTQyMjY2MzEzNTc1MgJMOTYzMjExNjUzNzQxMTQ3Mjk4MTQ2NDE0NzY0MDM5MzkxNzQxODQyMDI4NzgwOTUxODYyMTk5OTM0MjIwNjc2ODgzMjg0NzY5NTg5Nkw4NDM2Mjg3MTUwMzIxMjE2NTUwOTIxNTQ4ODg0MjI2MDM4MjczMTk0MjAyNDQwNTc0NzI5MDM4MTk2NDAxNDAzMDI0Mzg0MTEzODk4AgExATADTDUxNzIxODQyMDU0ODkxNDg4MzEwNTgxODkxNDIwNjI3Njc1NTM3MjMxMDkzNzIyMDk4NzI0NDAxMzA1MTg0MzYzODQxNzUxMjY1MjRMNTE1MTQzMjA2NjEzODc0NzIwOTEyMDY4NzUyMjIwODU1NDA0MTU2NDgyNzA4MDc5NzA1MDcxNjkyNzc2OTY0MzQ0NzQyMjEyMzI3MAExMXdpYVhOeklqb2lhSFIwY0hNNkx5OXBaQzUwZDJsMFkyZ3VkSFl2YjJGMWRHZ3lJaXcCMmV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNJc0ltdHBaQ0k2SWpFaWZRTTIwNjg3NjQyNTE3NjMwNzMzMjczNjg3Nzk1NDc2MjQ3NDM3NzQzODM0NjAxMTAxNTY2Njg0OTY3OTY3NzA1ODA5OTg1MjQxMDY1NTM5CgAAAAAAAABhANFnRWP0VWDZA6kp8ltYtndCLMp70+CQMkW4CKPMOF5fGqTuUIKzqHJysBK8jS3rgHHBc5ZDqn0YUG0W2SH5gQC5xu4WMO8+cRFEpkjbBruyKE9ydM++5T/87lA8waSSAAgABAANfas1jI2tqk76AEmnWwdDZVWxCjaCGbtoD3BXE0nXdQEBAg4XzVk55GsZZkGWjNdZkQuiV34n+nP944dtub7FvOsrAQIDR/uvI/A4q8TDCKJxEXoqTP+u3bxf+Bx1F7xsdKfttDABAzwbaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyLbzKbLI5Mq4c7y9X5gf73CthASNbTN9llO2Okr5TqEMBAQA=";

            let bcs = Base64::decode_vec(FIXTURE).unwrap();

            let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
            assert_eq!(SignatureScheme::Multisig, sig.scheme());
            let bytes = bcs::to_bytes(&sig).unwrap();
            assert_eq!(bcs, bytes);

            let json = serde_json::to_string_pretty(&sig).unwrap();
            println!("{json}");
            assert_eq!(sig, serde_json::from_str(&json).unwrap());
        }

        #[test]
        fn zklogin_fixtures() {
            const FIXTURES: &[&str]  = &[
                "mAcFA00yMTM0MzA3MTg2NDQ3ODc4NTU1OTU1OTY2Njg3NDQ3Njg0MzYyODQxNjA4OTQ4ODEyMTk4MjQ0OTY0ODk4OTg3OTkxMTI1MTY2OTA2N0w1MzYyMzAzOTQxMzk3NzQ1MTk2MTQxNjgxNjA5MDk0MDI4MTg3NzgxMzY2ODc3ODA5NTA2NTU0NzA3MjQ4MzcwNzM4OTcwOTI5MzYwATEDAk0xOTAzMjkyNDMyMDAxODEyNjcyNzEyMDYzMjYzMzM2OTE1NTg2MDc4NDA0NjY2MDcyMzIzMjU0MTAwMjQyODAxODA4ODQ4MTI3MzA5N0sxOTM0MDEzODQwOTcyNjc5OTM0MzgxMTI2ODg3OTQ2MTk1NDk5NTczMjY3NTE5ODAxNDA4MzQ2MzA3NDA2NzI3NjIxNzI0MTA4ODUCTDQxMTc0OTU3NjIwNzc2NjE4OTk2Njk5ODU1MTUzMzc2MDcwMTkzNTgwMjc2MjUxNTc4MDQwMTc0NTI2OTM1MTY5ODY1MDU1NDcyMTdNMTI3MDM0MzkzNTYyNTQ3NTM4NDA5NzAxMjA3MDAxMjM5MjcxOTU1OTI4OTE0MDgxMzY5NzQ0ODkwMzkzMzgyOTgzODYwODQxODYyNzYCATEBMANMNjAyNTg2MDg4MjI2OTUxNTE2NDY3MjY1NjU3OTU4MDE1OTMyMTI2ODY4MDM1NjU0NTkxOTA1NDkwNzkzNTM4MzY1NDYwNzA5MTIyOE0xNTUxNzY4ODA2NDc3NTgzMDI3NzAwNjY2NzE2OTM2NzAxNjU4Nzk5NDIyNjc1MTQ0Nzg5ODMzNjg0MDk5NjU4MDczNzg0NDY0NDExNQExMXdpYVhOeklqb2lhSFIwY0hNNkx5OXBaQzUwZDJsMFkyZ3VkSFl2YjJGMWRHZ3lJaXcCMmV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNJc0ltdHBaQ0k2SWpFaWZRTDIwMjIzNjc3MTc2ODYwNzEyNzk5MTIwNjA0MTY1NTc3MDEyMjMyOTk3NTc0MjQwNjg2MDUwMzc1OTc1MTI1NzUzNDA0NDU0MTY4MTAKAAAAAAAAAGICUv1c+GW7/G0rKAO5QgQrqs3ujZALi4GWTkqgEjfTqMs53H1MeeRJdWzJW104/97F1VJyjm01ozKRasbRJGSsRwKi14vTFJZpnOkPlaKtNt4cGpY4PpaoeXb289IzLDx1Gg==",
                "mwcFA00xMDE2MjI2MTYwOTg0NDYxNDI1OTY3MjA3OTg1MTYyNzUxNTQyNjEzMzM1OTEzMTc5NDQ3ODc4MDgzNDA3NTkxNDc5ODcxNzMzNzUzNU0xNjUwMTEzNTg2OTk2NDUwMDk1Njk2MDE2NzI0NzgwMzY3MzkyNDI4NDI0NTU3MDIyODMyODc4MDYxNjE4NzE0MzY2MzgzNzA0MjMyNAExAwJMNjAyMjIxMDk3ODA0MDA5MTgyMjQ1MDM2NjM2NjkyMzE1Mjg2NDAzMDQzNjY2ODg5NTUzNzYwNTM5MTM4MDA3OTAxMzIzMjE5OTk2NU0xNjEwNjE0MDY4NzEwMDc3MzQyNDIyNTI0NjEyNzM3ODIyNTgwOTIxMTQxMTYwMjQzMTIwMzI3NDM2MjM1NjEwOTI5NDk5Mjg2MjM4NgJMNzQwNDE3NTg3NDgyOTU3NDM0NTk1NDk1MTU0NDkxODY2ODI5ODQ0OTYxNjMzMDAyMzE4MzE4MzcwMTgxNjEwOTg3OTAwOTY5MTcxMUw3MzAwNzMwODk0MDQzNjM0NjI0NzIwNzkzNDIxNTM1NTUxODI3NDU4NjE4NzU5NjE2OTEzMjU0ODY4MzUzODE1MzM5ODg3MjIzMTA5AgExATADTTExNDA2NTA2NzUyNTkyODQ5NDk4MzcyNzYxODIyNzM4MjA2NTY0ODc4ODM3NTE3NzkxNTY2MzQ3NDk0NDkyNDQyMTI4MDExMTQwMzU3TTE1Njk5MzYzODA5ODg4MDc3MDcxNjM1NTg1MTA2NzA2MjE0NTcxMDI3NDU3ODE5MTE4NTE1NTk2MjA4MDgzODUzODcyOTM3NzQxNDczATExd2lhWE56SWpvaWFIUjBjSE02THk5cFpDNTBkMmwwWTJndWRIWXZiMkYxZEdneUlpdwIyZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0lzSW10cFpDSTZJakVpZlFNMTc1NzI2MTY4NDgyNzU4OTMzODIyMTc0ODE3OTM5MTkwMDYzNjYzNzY4NTk4MTcwNDA1NDYwNDk4MzU5NTgxODc0NjEyOTg2NjkyNzAKAAAAAAAAAGICl9lwjktCQkH7GqGGV6EdbjHv4Go6MIDmr6EIvtg/2h5IuXKJF5GoVLuykxWwkSdNr9iRUZaz3Z0p/Z9nPJlW/gNaiwdVCMdfShJHSZgqfSH4DZpfaJPkGp6VX+TIIeDevg==",
                "mgcFA00xOTUwNDI1NDE5MzgxMzM3OTA5NDA1MzkyODkyNTQwMjAxMjIxMTg4ODY5MDAzOTQ3ODM0MjYzOTk4OTcwMjA4MjAxNjY2MDkyNzg4MU0xODEwMjYxODU0NjY0NjY3MDgyMjI5MjczMjIwMDgzMzU0OTk4NDAxMTkxMDI1MDY2MjQ4Mjk5MjMzODgzNjA1NTc1MzMyNTUyMTUzMwExAwJMNTI0MzA1OTQ2MTI1NDQxOTM0NzgzOTMxMjI4ODQ5NjY4OTI0Njk4NzIyMTMyMDcxMDcyNzc2NzgzNzc3NDc4ODI4Mzc1NjgzMTAyOE0xMjA3MDIwMzk2MzAzNjY0NTY2NjAyMzUwNDMyNDM3NDY1OTYwMTY1NzY2NDAzOTU4MzE0MDU2Njc2MDExOTcwMTA3MjI5MjA0NzkxMQJNMTYzNjc2NDUxMTMxNzA1OTkxMTgwNzc1NjgxOTUyMjA5ODY1NjcxNjE0ODk2MDcyNDI1NzQ2ODg5ODQ0NzI4NTk0MzE2Mzk4MzQxNzhMNTg5MTQ4MzY3MjI1MTQyMzgzODE5NTQxNDg0NjEwNTY0Nzk4MDE2NjAyODIyNjcwMzE2ODE1Njg2MzkzNjUxNjk1OTkzMjE4MzExNQIBMQEwA0w2NDc2MTA0MzAwODgxNTQ2NTk3NjUwODk0NjEzNTUyMDc1NDg4Mjk5NjA4NjM5MTY4MzE3MjgzNTg2ODI3MDA3MTUzODg5MjI1MTI2TDQ3NjgzNjQxMTE1NjM0NzI0MDI1NzA4NDE0ODEyMDMzMTgzMDQzMTQ1MDQ4NjcxMzk1NzQ0MzAzODI2NzA4MDcwMTkwNDgxMTQyNzEBMTF3aWFYTnpJam9pYUhSMGNITTZMeTlwWkM1MGQybDBZMmd1ZEhZdmIyRjFkR2d5SWl3AjJleUpoYkdjaU9pSlNVekkxTmlJc0luUjVjQ0k2SWtwWFZDSXNJbXRwWkNJNklqRWlmUU0xMDc0MzE4MDg0MjY5ODE2Mzk0ODQ5NzAyMjkwMDE0Mzc4NjI0MTEwOTYyMzMyMDgzNzYxNzUzMDY5NzUxNDA1MzIwODA1NjEwNzgzNAoAAAAAAAAAYgLL7Jn3QV4USqVbuv97w4LqA12BAwU95fsUrvymgAUPtiepsG6kCVnX903PFZBusNM07tgWJ4/5ypb5mbJQhijJA+3BG7HM6kM2jZ0NPldx4AR5zvu+l4ZXRC4lo39h/K5s",
                "mgcFA0wxNjY4NTEwOTQ1NDY2OTQ2OTYyODUxODAzOTg1MTA3Mjk2NTM1OTM3MzI1NzI5OTMzNDE1MzAzOTcwNjI2MjE3NzAwOTM0NjE4MjY1TDc5ODAxMjUwNTYxMTA2NzczMjY0NjA1MjI0MjgyNTk1OTM4NzQzOTg5MjE3Nzg1Mzk1MTUxODY3MTkwMzk3OTc1MTQ0NDA4ODQ1NTEBMQMCTTEyODA2ODY2NjkyMTUxODMxMTI1MzExMTk3Nzc1NTAxNDU1MTIwNzQwNjg2Mzk2OTQ4NDIxMjAyODI0MjkwODMwNzQzMzM4NTE1MjMxTTE4NzY2Mzc4MTcwNzE4MDMzMzk0ODQxMTYxMTU0MjA0NDA2ODc0MDM0ODk4NjA1NTk4MTgzMDM5NjM2NjQ1NjU3Mjk3NTIzMTU4ODU1Ak0xNzYyNTIzNTA0NzgxNDg2NDg1OTY1NTA1MTkyNTUyMzYxNjkwNzg2MDk3MjM3ODE1OTU1NjA4NDMyNDM5NTQxODk5MzI4NzQwMzk0M00xNjQ3MTA2MDIyOTUzMDIyNjEwOTk0Mzc3MTU3NzQ1NjIzMDM2NTM5NTMxNzM0NDk3OTAwNjAwMTE1NTgxNzM5ODE1NjczMjIwMjcxMwIBMQEwA00xODU1NzU4NTE1MjgxMTk5Mzk1MTY2NDY4NDA1ODg4MTg0NDE2MjY4NTk1NzAxMDY1MzIyNjg5ODkyOTgwNjA1Njc4NjMyMzg5MzA0M0wyNDQ2NDI2NDg4NTQwNzcwNzE5NTIyMjk1NTY3Njc2OTU3MzYzNjIxNTQ0MDUwMTg5OTAxMTk0MTY3NDY1NDE3OTA0Njk2NDQ3NDA1ATExd2lhWE56SWpvaWFIUjBjSE02THk5cFpDNTBkMmwwWTJndWRIWXZiMkYxZEdneUlpdwIyZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0lzSW10cFpDSTZJakVpZlFMODQ2ODk2NzMyOTAyOTgzNjU0MjM3MzIzMjc4Njc3NzgyNDA5MTgyOTM1OTA4MjczNzA5MjQ3MjM1NDEwODEzNTkwOTE0MTM4MjEwNAoAAAAAAAAAYgEaWZZP7C934LS3vgsXYQk85BBiG6E285TY0C6U59qaUxlCUQWACVbxyEej193U4uIIP71lZ6KwvfT7lqOsUUIvAoa8xwWZ68Qgs7iXfsxg5ZS7VnSb6qVi1/gKm9//yqod",
                "lgcFA0w2MjczOTkyOTQ0MjgyNjU2MjQxNjQzMjQ5OTY3NTQ2NDM2NDE1NjgzNTM4MzMwMDczMzA5MDM4Mjk1MDkwMDIwNDM3MDMyNzM0NDE3TTEzOTI1MTMxOTE1MzgzODQzMDk5Mzg1NTU1NjI2MjcyMDMyOTYxOTIzNzI2NTgwMjI2Njk3MDE1MzE5MTk3MTMyMTg5MTE4NjA1MjU3ATEDAkw3NzA0MDA3NjE0MTIwMjQ0NDI4MjAzMjM0MDMyNzc0Njg5MDgxMDc4NjM4ODY5MzE3MjQzNTUxMjUzMDEwNzI2MzM4NTEwNDM2MTI3TDQ3MzM2OTE1NjYwMDgxOTEyMDQwMTI3MDU3OTkwNjIyNzU5NjI2NDczMDE1MjQ1NzAyMTIzNDM3MzI3NTExNzE0MjI2NjMxMzU3NTICTDk2MzIxMTY1Mzc0MTE0NzI5ODE0NjQxNDc2NDAzOTM5MTc0MTg0MjAyODc4MDk1MTg2MjE5OTkzNDIyMDY3Njg4MzI4NDc2OTU4OTZMODQzNjI4NzE1MDMyMTIxNjU1MDkyMTU0ODg4NDIyNjAzODI3MzE5NDIwMjQ0MDU3NDcyOTAzODE5NjQwMTQwMzAyNDM4NDExMzg5OAIBMQEwA0w1MTcyMTg0MjA1NDg5MTQ4ODMxMDU4MTg5MTQyMDYyNzY3NTUzNzIzMTA5MzcyMjA5ODcyNDQwMTMwNTE4NDM2Mzg0MTc1MTI2NTI0TDUxNTE0MzIwNjYxMzg3NDcyMDkxMjA2ODc1MjIyMDg1NTQwNDE1NjQ4MjcwODA3OTcwNTA3MTY5Mjc3Njk2NDM0NDc0MjIxMjMyNzABMTF3aWFYTnpJam9pYUhSMGNITTZMeTlwWkM1MGQybDBZMmd1ZEhZdmIyRjFkR2d5SWl3AjJleUpoYkdjaU9pSlNVekkxTmlJc0luUjVjQ0k2SWtwWFZDSXNJbXRwWkNJNklqRWlmUU0yMDY4NzY0MjUxNzYzMDczMzI3MzY4Nzc5NTQ3NjI0NzQzNzc0MzgzNDYwMTEwMTU2NjY4NDk2Nzk2NzcwNTgwOTk4NTI0MTA2NTUzOQoAAAAAAAAAYQBn1v6x7RD9EyaiubLQ8qQkJSNI2Mr1GFHXZyOUJ+eCphFkwjYKBo44TMAbryd405BY+MHYTFLZOD06UTycKHgKucbuFjDvPnERRKZI2wa7sihPcnTPvuU//O5QPMGkkgA=",
            ];

            for fixture in FIXTURES {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
                assert_eq!(SignatureScheme::ZkLogin, sig.scheme());
                let bytes = bcs::to_bytes(&sig).unwrap();
                assert_eq!(bcs, bytes);

                let json = serde_json::to_string_pretty(&sig).unwrap();
                println!("{json}");
                assert_eq!(sig, serde_json::from_str(&json).unwrap());
            }
        }

        #[test]
        fn passkey_fixtures() {
            const FIXTURES: &[&str]  = &[
                "lgIGJUmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjHQAAAACKAXsidHlwZSI6IndlYmF1dGhuLmdldCIsImNoYWxsZW5nZSI6IkFBQUF0X21qSUIxdmJWcFlNNldWNllfb2l4Nko4YU5fOXNiOFNLRmJ1a0JmaVF3Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1MTczIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfWICmOyQv1fJ+inKD0C/sxKtxyFKl9aoBign6p9Ih3iA2ahDVg2CPZqUOlEhur2S2GbIZjbn6TbgWtbXXg8SjLkL7wM9Fw4JO0AKLdnLC1nhQguHBX5K6Hv2ta1sqoOqEFDDEw==",
            ];

            for fixture in FIXTURES {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
                assert_eq!(SignatureScheme::Passkey, sig.scheme());
                let bytes = bcs::to_bytes(&sig).unwrap();
                assert_eq!(bcs, bytes);

                let json = serde_json::to_string_pretty(&sig).unwrap();
                println!("{json}");
                assert_eq!(sig, serde_json::from_str(&json).unwrap());
            }
        }
    }
}
