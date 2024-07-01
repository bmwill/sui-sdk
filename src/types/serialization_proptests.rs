use crate::types::*;
use test_strategy::proptest;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

macro_rules! serialization_test {
    ($type:ident) => {
        paste::item! {
            #[cfg_attr(target_arch = "wasm32", proptest(cases = 50))]
            #[cfg_attr(not(target_arch = "wasm32"), proptest)]
            #[allow(non_snake_case)]
            fn [< test_valid_json_schema_ $type >] (instance: $type) {
                assert_valid_json_schema(&instance);
            }

            #[cfg_attr(target_arch = "wasm32", proptest(cases = 50))]
            #[cfg_attr(not(target_arch = "wasm32"), proptest)]
            #[allow(non_snake_case)]
            fn [< test_roundtrip_ $type >] (instance: $type) {
                assert_roundtrip(&instance);
            }

            #[proptest]
            #[allow(non_snake_case)]
            fn [< fuzz_deserialization_ $type >] (
                #[strategy(proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..=2048))]
                bytes: Vec<u8>,
            ) {
                let _: Result<$type, _> = bcs::from_bytes(&bytes);
            }
        }
    };
}

fn assert_valid_json_schema<T>(instance: &T)
where
    T: serde::Serialize + schemars::JsonSchema,
{
    let root_schema = schemars::gen::SchemaGenerator::default().into_root_schema_for::<T>();
    let schema = serde_json::json!(root_schema);
    let compiled = jsonschema::JSONSchema::compile(&schema).unwrap();
    let instance = serde_json::json!(instance);

    let result = compiled.validate(&instance);
    let r = result.is_ok();
    if let Err(errors) = result {
        for error in errors {
            println!("Validation error: {}", error);
            println!("Instance path: {}", error.instance_path);
        }
    }

    // assert!(compiled.is_valid(&instance));
    assert!(r);
}

fn assert_roundtrip<T>(instance: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    // println!("{instance:?}");
    let bcs_bytes = bcs::to_bytes(instance).unwrap();
    let deser_from_bcs_bytes = bcs::from_bytes::<T>(&bcs_bytes).unwrap();
    assert_eq!(instance, &deser_from_bcs_bytes);

    let json = serde_json::to_string(instance).unwrap();
    let deser_from_json = serde_json::from_str::<T>(&json).unwrap();
    assert_eq!(instance, &deser_from_json);
}

serialization_test!(Address);
serialization_test!(CheckpointCommitment);
serialization_test!(CheckpointContents);
serialization_test!(CheckpointData);
serialization_test!(CheckpointSequenceNumber);
serialization_test!(CheckpointSummary);
serialization_test!(CheckpointTimestamp);
serialization_test!(CheckpointTransaction);
serialization_test!(CheckpointTransactionInfo);
serialization_test!(EndOfEpochData);
serialization_test!(SignedCheckpointSummary);
serialization_test!(Bls12381PublicKey);
serialization_test!(Bls12381Signature);
serialization_test!(Bn254FieldElement);
serialization_test!(Claim);
serialization_test!(Ed25519PublicKey);
serialization_test!(Ed25519Signature);
serialization_test!(Jwk);
serialization_test!(JwkId);
serialization_test!(JwtDetails);
serialization_test!(MultisigAggregatedSignature);
serialization_test!(MultisigCommittee);
serialization_test!(MultisigMember);
serialization_test!(MultisigMemberPublicKey);
serialization_test!(MultisigMemberSignature);
serialization_test!(Secp256k1PublicKey);
serialization_test!(Secp256k1Signature);
serialization_test!(Secp256r1PublicKey);
serialization_test!(Secp256r1Signature);
serialization_test!(SimpleSignature);
serialization_test!(UserSignature);
serialization_test!(ValidatorAggregatedSignature);
serialization_test!(ValidatorCommittee);
serialization_test!(ValidatorCommitteeMember);
serialization_test!(ValidatorSignature);
serialization_test!(ZkLoginAuthenticator);
serialization_test!(ZkLoginInputs);
serialization_test!(ZkLoginProof);
serialization_test!(ZkLoginPublicIdentifier);
serialization_test!(CircomG1);
serialization_test!(CircomG2);
serialization_test!(PasskeyAuthenticator);
serialization_test!(CheckpointContentsDigest);
serialization_test!(CheckpointDigest);
serialization_test!(ConsensusCommitDigest);
serialization_test!(Digest);
serialization_test!(EffectsAuxiliaryDataDigest);
serialization_test!(ObjectDigest);
serialization_test!(TransactionDigest);
serialization_test!(TransactionEffectsDigest);
serialization_test!(TransactionEventsDigest);
serialization_test!(ChangedObject);
serialization_test!(EffectsObjectChange);
serialization_test!(IdOperation);
serialization_test!(ModifiedAtVersion);
serialization_test!(ObjectIn);
serialization_test!(ObjectOut);
serialization_test!(ObjectReferenceWithOwner);
serialization_test!(TransactionEffects);
serialization_test!(TransactionEffectsV1);
serialization_test!(TransactionEffectsV2);
serialization_test!(UnchangedSharedKind);
serialization_test!(UnchangedSharedObject);
serialization_test!(BalanceChange);
serialization_test!(Event);
serialization_test!(TransactionEvents);
serialization_test!(CommandArgumentError);
serialization_test!(ExecutionError);
serialization_test!(ExecutionStatus);
serialization_test!(MoveLocation);
serialization_test!(PackageUpgradeError);
serialization_test!(TypeArgumentError);
serialization_test!(GasCostSummary);
serialization_test!(GenesisObject);
serialization_test!(Object);
serialization_test!(ObjectReference);
serialization_test!(Owner);
serialization_test!(TypeOrigin);
serialization_test!(UpgradeInfo);
serialization_test!(ObjectId);
serialization_test!(ActiveJwk);
serialization_test!(Argument);
serialization_test!(AuthenticatorStateExpire);
serialization_test!(AuthenticatorStateUpdate);
serialization_test!(ChangeEpoch);
serialization_test!(Command);
serialization_test!(ConsensusCommitPrologue);
serialization_test!(ConsensusCommitPrologueV2);
serialization_test!(ConsensusCommitPrologueV3);
serialization_test!(CancelledTransaction);
serialization_test!(ConsensusDeterminedVersionAssignments);
serialization_test!(VersionAssignment);
serialization_test!(EndOfEpochTransactionKind);
serialization_test!(GasPayment);
serialization_test!(GenesisTransaction);
serialization_test!(InputArgument);
serialization_test!(MakeMoveVector);
serialization_test!(MergeCoins);
serialization_test!(MoveCall);
serialization_test!(ProgrammableTransaction);
serialization_test!(Publish);
serialization_test!(RandomnessStateUpdate);
serialization_test!(SignedTransaction);
serialization_test!(SplitCoins);
serialization_test!(SystemPackage);
serialization_test!(Transaction);
serialization_test!(TransactionExpiration);
serialization_test!(TransactionKind);
serialization_test!(TransferObjects);
// serialization_test!(UnresolvedGasPayment);
// serialization_test!(UnresolvedInputArgument);
// serialization_test!(UnresolvedObjectReference);
// serialization_test!(UnresolvedProgrammableTransaction);
// serialization_test!(UnresolvedTransaction);
serialization_test!(Upgrade);
serialization_test!(Identifier);
serialization_test!(StructTag);
serialization_test!(TypeTag);
