use bus_mapping::circuit_input_builder::CircuitsParams;
use eth_types::geth_types::GethData;
use halo2_proofs::{
    circuit::Value,
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverGWC, VerifierGWC},
        strategy::SingleStrategy,
    },
    SerdeFormat,
};
use mock::MockBlock;
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use snark_verifier::system::halo2::{compile, Config};
use std::{
    fs::File,
    io::{Read, Write},
};
use zkevm_circuits::{
    root_circuit::{PoseidonTranscript, RootCircuit},
    super_circuit,
};

const MAX_TXS: usize = 0;
const MAX_CALLDATA: usize = 32;
type SuperCircuit = super_circuit::SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, 0x101>;

fn main() {
    let params = read_or_create_params("./params-12", 12);
    let (super_circuit, super_circuit_instance) = {
        let eth_block = MockBlock::default().into();
        let geth_data = GethData {
            chain_id: 1.into(),
            history_hashes: vec![],
            eth_block,
            geth_traces: vec![],
            accounts: vec![],
        };
        let circuits_params = CircuitsParams {
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_rws: 256,
            max_copy_rows: 256,
            max_exp_steps: 256,
            max_bytecode: 512,
            max_evm_rows: 0,
            keccak_padding: None,
        };
        let (_, circuit, instance, _) = SuperCircuit::build(geth_data, circuits_params).unwrap();
        MockProver::run(12, &circuit, instance.clone())
            .unwrap()
            .assert_satisfied_par();
        (circuit, instance)
    };
    let super_circuit_pk = read_or_create_pk("./super_circuit_pk", &params, &super_circuit);
    let super_circuit_proof = read_or_create_proof(
        "./super_circuit_proof",
        &params,
        &super_circuit_pk,
        super_circuit,
        &super_circuit_instance,
    );

    let protocol = compile(
        &params,
        super_circuit_pk.get_vk(),
        Config::kzg().with_num_instance(super_circuit_instance.iter().map(|i| i.len()).collect()),
    );
    let root_circuit = RootCircuit::new(
        &params,
        &protocol,
        Value::known(&super_circuit_instance),
        Value::known(&super_circuit_proof),
    )
    .unwrap();
    let root_circuit_instnace = root_circuit.instance();
    let params = read_or_create_params("./params-26", 26);
    let root_circuit_pk = read_or_create_pk(
        "root_circuit_pk",
        &params,
        &root_circuit.without_witnesses(),
    );
    read_or_create_proof(
        "root_circuit_proof",
        &params,
        &root_circuit_pk,
        root_circuit,
        &root_circuit_instnace,
    );
}

fn read_or_create_params(path: &str, k: u32) -> ParamsKZG<Bn256> {
    File::open(path)
        .map(|mut file| {
            ParamsKZG::<Bn256>::read_custom(&mut file, SerdeFormat::RawBytesUnchecked).unwrap()
        })
        .unwrap_or_else(|_| {
            let mut rng = StdRng::seed_from_u64(9);
            let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
            params
                .write_custom(
                    &mut File::create(path).unwrap(),
                    SerdeFormat::RawBytesUnchecked,
                )
                .unwrap();
            params
        })
}

fn read_or_create_pk<C: Circuit<Fr>>(
    path: &str,
    params: &ParamsKZG<Bn256>,
    circuit: &C,
) -> ProvingKey<G1Affine> {
    File::open(path)
        .map(|mut file| {
            ProvingKey::read::<_, C>(&mut file, SerdeFormat::RawBytesUnchecked).unwrap()
        })
        .unwrap_or_else(|_| {
            let vk = keygen_vk(params, circuit).unwrap();
            let pk = keygen_pk(params, vk, circuit).unwrap();
            pk.write(
                &mut File::create(path).unwrap(),
                SerdeFormat::RawBytesUnchecked,
            )
            .unwrap();
            pk
        })
}

fn read_or_create_proof(
    path: &str,
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: impl Circuit<Fr>,
    instance: &[Vec<Fr>],
) -> Vec<u8> {
    File::open(path)
        .map(|mut file| {
            let mut proof = Vec::new();
            file.read_to_end(&mut proof).unwrap();

            let instance = instance.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let instance = vec![instance.as_slice()];
            let mut transcript = PoseidonTranscript::new(proof.as_slice());
            verify_proof::<_, VerifierGWC<_>, _, _, _>(
                params,
                pk.get_vk(),
                SingleStrategy::new(params),
                &instance,
                &mut transcript,
            )
            .unwrap();

            proof
        })
        .unwrap_or_else(|_| {
            let instance = instance.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let instance = vec![instance.as_slice()];
            let proof = {
                let mut rng = OsRng;
                let mut transcript = PoseidonTranscript::<_, _>::new(Vec::new());
                create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
                    params,
                    pk,
                    &[circuit],
                    &instance,
                    &mut rng,
                    &mut transcript,
                )
                .unwrap();
                transcript.finalize()
            };

            let mut transcript = PoseidonTranscript::new(proof.as_slice());
            verify_proof::<_, VerifierGWC<_>, _, _, _>(
                params,
                pk.get_vk(),
                SingleStrategy::new(params),
                &instance,
                &mut transcript,
            )
            .unwrap();

            File::create(path).unwrap().write_all(&proof).unwrap();

            proof
        })
}
