use crate::types::Digest;

use super::{Secp256r1PublicKey, Secp256r1Signature};

/// An passkey authenticator with parsed fields. See field defition below. Can be initialized from [struct RawPasskeyAuthenticator].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAuthenticator {
    /// Compact r1 public key upon passkey creation.
    /// Initialized from `user_signature` in `RawPasskeyAuthenticator`.
    public_key: Secp256r1PublicKey,

    /// Normalized r1 signature returned by passkey.
    /// Initialized from `user_signature` in `RawPasskeyAuthenticator`.
    signature: Secp256r1Signature,

    /// Valid intent parsed from the first 3 bytes of `client_data_json.challenge`.
    intent: [u8; 3],

    /// Valid tx_digest parsed from the last 32 bytes of `client_data_json.challenge`.
    digest: Digest,

    /// `authenticatorData` is a bytearray that encodes
    /// [Authenticator Data](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data)
    /// structure returned by the authenticator attestation
    /// response as is.
    authenticator_data: Vec<u8>,

    /// `clientDataJSON` contains a JSON-compatible
    /// UTF-8 encoded serialization of the client
    /// data which is passed to the authenticator by
    ///  the client during the authentication request
    /// (see [CollectedClientData](https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata))
    client_data_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyPublicKey(Secp256r1PublicKey);

impl PasskeyPublicKey {
    pub fn inner(&self) -> &Secp256r1PublicKey {
        &self.0
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use crate::types::SignatureScheme;
    use crate::types::SimpleSignature;

    use super::*;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serialize;
    use serde::Serializer;
    use serde_with::Bytes;
    use serde_with::DeserializeAs;
    use std::borrow::Cow;

    #[derive(serde::Serialize)]
    struct AuthenticatorRef<'a> {
        authenticator_data: &'a Vec<u8>,
        client_data_json: &'a String,
        signature: SimpleSignature,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename = "PasskeyAuthenticator")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    struct Authenticator {
        authenticator_data: Vec<u8>,
        client_data_json: String,
        signature: SimpleSignature,
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for PasskeyAuthenticator {
        fn schema_name() -> String {
            Authenticator::schema_name()
        }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            Authenticator::json_schema(gen)
        }
    }

    impl Serialize for PasskeyAuthenticator {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let authenticator_ref = AuthenticatorRef {
                authenticator_data: &self.authenticator_data,
                client_data_json: &self.client_data_json,
                signature: SimpleSignature::Secp256r1 {
                    signature: self.signature,
                    public_key: self.public_key,
                },
            };

            if serializer.is_human_readable() {
                authenticator_ref.serialize(serializer)
            } else {
                let mut buf = Vec::new();
                buf.push(SignatureScheme::Passkey as u8);

                bcs::serialize_into(&mut buf, &authenticator_ref)
                    .expect("serialization cannot fail");
                serializer.serialize_bytes(&buf)
            }
        }
    }

    impl<'de> Deserialize<'de> for PasskeyAuthenticator {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let authenticator = Authenticator::deserialize(deserializer)?;
                Self::try_from_raw(authenticator)
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_serialized_bytes(bytes)
            }
        }
    }

    impl PasskeyAuthenticator {
        fn try_from_raw<E: serde::de::Error>(
            Authenticator {
                authenticator_data,
                client_data_json,
                signature,
            }: Authenticator,
        ) -> Result<Self, E> {
            let SimpleSignature::Secp256r1 {
                signature,
                public_key,
            } = signature
            else {
                return Err(serde::de::Error::custom(
                    "expected passkey with secp256r1 signature",
                ));
            };

            let CollectedClientData {
                ty: _,
                challenge,
                origin: _,
            } = serde_json::from_str(&client_data_json).map_err(serde::de::Error::custom)?;

            // challenge is 3 byte intent | 32 byte hash
            let mut challenge_buf = [0; 3 + Digest::LENGTH];

            // decode unpadded url endoded base64 data per spec:
            // https://w3c.github.io/webauthn/#base64url-encoding
            <base64ct::Base64UrlUnpadded as base64ct::Encoding>::decode(
                challenge,
                &mut challenge_buf,
            )
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "unable to decode base64urlunpadded into 3-byte intent and 32-byte digest: {e}"
                ))
            })?;

            let intent = challenge_buf[..3].try_into().unwrap();
            let digest = challenge_buf[3..].try_into().unwrap();

            Ok(Self {
                public_key,
                signature,
                intent,
                digest: Digest::new(digest),
                authenticator_data,
                client_data_json,
            })
        }

        pub(crate) fn from_serialized_bytes<T: AsRef<[u8]>, E: serde::de::Error>(
            bytes: T,
        ) -> Result<Self, E> {
            let bytes = bytes.as_ref();
            let flag = SignatureScheme::from_byte(
                *bytes
                    .first()
                    .ok_or_else(|| serde::de::Error::custom("missing signature scheme flag"))?,
            )
            .map_err(serde::de::Error::custom)?;
            if flag != SignatureScheme::Passkey {
                return Err(serde::de::Error::custom("invalid passkey flag"));
            }
            let bcs_bytes = &bytes[1..];

            let authenticator = bcs::from_bytes(bcs_bytes).map_err(serde::de::Error::custom)?;

            Self::try_from_raw(authenticator)
        }
    }

    /// The client data represents the contextual bindings of both the Relying Party and the client.
    /// It is a key-value mapping whose keys are strings. Values can be any type that has a valid
    /// encoding in JSON.
    ///
    /// > Note: The [`CollectedClientData`] may be extended in the future. Therefore it’s critical when
    /// >       parsing to be tolerant of unknown keys and of any reordering of the keys
    ///
    /// This struct conforms to the JSON byte serialization format expected of `CollectedClientData`,
    /// detailed in section [5.8.1.1 Serialization] of the WebAuthn spec. Namely the following
    /// requirements:
    ///
    /// * `type`, `challenge`, `origin`, `crossOrigin` must always be present in the serialized format
    ///   _in that order_.
    ///
    /// <https://w3c.github.io/webauthn/#dictionary-client-data>
    ///
    /// [5.8.1.1 Serialization]: https://w3c.github.io/webauthn/#clientdatajson-serialization
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CollectedClientData {
        /// This member contains the value [`ClientDataType::Create`] when creating new credentials, and
        /// [`ClientDataType::Get`] when getting an assertion from an existing credential. The purpose
        /// of this member is to prevent certain types of signature confusion attacks (where an attacker
        ///  substitutes one legitimate signature for another).
        #[serde(rename = "type")]
        pub ty: ClientDataType,

        /// This member contains the base64url encoding of the challenge provided by the Relying Party.
        /// See the [Cryptographic Challenges] security consideration.
        ///
        /// [Cryptographic Challenges]: https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
        ///
        /// https://w3c.github.io/webauthn/#base64url-encoding
        ///
        /// The term Base64url Encoding refers to the base64 encoding using the URL- and filename-safe
        /// character set defined in Section 5 of [RFC4648], with all trailing '=' characters omitted
        /// (as permitted by Section 3.2) and without the inclusion of any line breaks, whitespace, or
        /// other additional characters.
        pub challenge: String,

        /// This member contains the fully qualified origin of the requester, as provided to the
        /// authenticator by the client, in the syntax defined by [RFC6454].
        ///
        /// [RFC6454]: https://www.rfc-editor.org/rfc/rfc6454
        pub origin: String,
        // /// This OPTIONAL member contains the inverse of the sameOriginWithAncestors argument value that
        // /// was passed into the internal method
        // #[serde(default, serialize_with = "truthiness")]
        // #[serde(rename = "type")]
        // pub cross_origin: Option<bool>,
    }

    /// Used to limit the values of [`CollectedClientData::ty`] and serializes to static strings.
    #[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
    pub enum ClientDataType {
        /// Serializes to the string `"webauthn.get"`
        ///
        /// Passkey's in Sui only support the value `"webauthn.get"`, other values will be rejected.
        #[serde(rename = "webauthn.get")]
        Get,
        // /// Serializes to the string `"webauthn.create"`
        // #[serde(rename = "webauthn.create")]
        // Create,
        // /// Serializes to the string `"payment.get"`
        // /// This variant is part of the Secure Payment Confirmation specification
        // ///
        // /// See <https://www.w3.org/TR/secure-payment-confirmation/#client-extension-processing-authentication>
        // #[serde(rename = "payment.get")]
        // PaymentGet,
    }
}

#[cfg(test)]
impl proptest::arbitrary::Arbitrary for PasskeyAuthenticator {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{collection::vec, prelude::*};
        use serialization::ClientDataType;
        use serialization::CollectedClientData;

        (
            any::<Secp256r1PublicKey>(),
            any::<Secp256r1Signature>(),
            any::<Digest>(),
            any::<[u8; 3]>(),
            vec(any::<u8>(), 0..32),
        )
            .prop_map(
                |(public_key, signature, digest, intent, authenticator_data)| {
                    let mut challenge_buf = Vec::new();
                    challenge_buf.extend_from_slice(&intent);
                    challenge_buf.extend_from_slice(digest.inner());
                    let challenge =
                        <base64ct::Base64UrlUnpadded as base64ct::Encoding>::encode_string(
                            &challenge_buf,
                        );
                    let client_data_json = serde_json::to_string(&CollectedClientData {
                        ty: ClientDataType::Get,
                        challenge,
                        origin: "http://example.com".to_owned(),
                    })
                    .unwrap();

                    Self {
                        public_key,
                        signature,
                        intent,
                        digest,
                        authenticator_data,
                        client_data_json,
                    }
                },
            )
            .boxed()
    }
}
