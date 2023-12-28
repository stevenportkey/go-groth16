use crate::dto::ProvingOutput;
use crate::utils;
use anyhow::Context;
use ark_bn254::Bn254;
use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
use ark_ec::pairing::Pairing;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use num_bigint::BigInt;
use num_traits::Num;
use rand::thread_rng;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;


pub struct ProvingContext<P: Pairing> {
    pub(crate) cfg: CircomConfig<P>,
    pub(crate) pk: ProvingKey<P>,
}

#[derive(Debug)]
struct InvalidPathError;

impl Display for InvalidPathError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "path is not valid")
    }
}

impl std::error::Error for InvalidPathError {}

#[derive(Debug)]
struct BuildError;

impl Display for BuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "path is not valid")
    }
}

impl std::error::Error for BuildError {}

pub(crate) fn to_vec(vk: *const cty::c_char, vk_len: cty::c_int) -> Vec<u8> {
    unsafe {
        let mut res = Vec::new();
        for i in 0..vk_len {
            let byte = *vk.offset(i as isize);
            res.push(byte as u8);
        }
        res
    }
}

pub(crate) fn parse_input<P: Pairing>(
    input: *const cty::c_char,
    input_len: cty::c_int,
) -> anyhow::Result<Vec<P::ScalarField>> {
    let mut inputs_vec = Vec::new();

    for i in 0..((input_len / 32) as isize) {
        let scalar_vec = unsafe { to_vec(input.offset(i * 32), 32) };
        let scalar = <P>::ScalarField::deserialize_compressed(&*scalar_vec)?;
        inputs_vec.push(scalar);
    }
    Ok(inputs_vec)
}

pub(crate) fn do_verify<P: Pairing>(
    vk: *const cty::c_char,
    vk_len: cty::c_int,
    inputs: *const cty::c_char,
    input_len: cty::c_int,
    proof: *const cty::c_char,
    proof_len: cty::c_int,
) -> anyhow::Result<bool> {
    let vk = utils::to_vec(vk, vk_len);
    let proof = utils::to_vec(proof, proof_len);
    let input = utils::parse_input::<P>(inputs, input_len)?;

    let vk = VerifyingKey::<P>::deserialize_compressed(&*vk)?;
    let pvk = prepare_verifying_key(&vk);

    let proof = Proof::deserialize_compressed(&*proof)?;
    let res = Groth16::<P>::verify_with_processed_vk(&pvk, input.as_slice(), &proof)?;
    Ok(res)
}

pub(crate) fn load_context(
    wasm_path: &str,
    r1cs_path: &str,
    zkey_path: &str,
) -> anyhow::Result<ProvingContext<Bn254>> {
    let cfg = CircomConfig::new(wasm_path, r1cs_path)
        .map_err(|_| InvalidPathError)
        .context("invalid wasm or r1cs file path")?;
    let mut zkey_file = File::open(zkey_path).context("invalid zkey file")?;
    let (pk, _) = read_zkey(&mut zkey_file).context("failed to load zkey")?;
    Ok(ProvingContext { cfg, pk })
}

pub(crate) fn ret_or_err<T, E>(res: Result<T, E>) -> *mut T
where
    E: Debug + Display,
{
    match res {
        Ok(res) => Box::into_raw(Box::new(res)),
        Err(_e) => std::ptr::null_mut(),
    }
}

fn parse_proving_input(input: &str) -> anyhow::Result<HashMap<String, Vec<BigInt>>> {
    let input: HashMap<String, Vec<String>> =
        serde_json::from_str(input).context("failed to parse JSON")?;

    let mut parsed_input = HashMap::new();

    for (key, values) in input {
        let converted_values: Vec<BigInt> = values
            .into_iter()
            .map(|s| BigInt::from_str_radix(&s, 10).unwrap_or_else(|_| BigInt::from(0)))
            .collect();

        parsed_input.insert(key, converted_values);
    }

    Ok(parsed_input)
}

pub(crate) fn do_prove<P: Pairing>(
    ctx: &ProvingContext<P>,
    input: &str,
) -> anyhow::Result<(Vec<P::ScalarField>, Proof<P>)> {
    let input = parse_proving_input(input).context("failed to parse input")?;
    let mut builder = CircomBuilder::new(ctx.cfg.clone());
    for (key, value) in input.iter() {
        for item in value {
            builder.push_input(key, item.clone());
        }
    }

    let circom = builder
        .build()
        .map_err(|_| BuildError)
        .context("failed to build circuit")?;

    let pub_inputs = circom
        .get_public_inputs()
        .context("failed to get public inputs")?;

    let mut rng = thread_rng();

    let cs = ConstraintSystem::<P::ScalarField>::new_ref();
    circom.clone().generate_constraints(cs.clone()).unwrap();
    let is_satisfied = cs.is_satisfied().unwrap();
    assert!(is_satisfied);

    let proof = Groth16::<P, CircomReduction>::prove(&ctx.pk, circom, &mut rng)
        .context("failed to produce proof")?;

    Ok((pub_inputs, proof))
}

pub(crate) fn write_to_buffer(
    output: &String,
    buf: *mut cty::c_char,
    max_len: cty::c_int,
) -> cty::c_int {
    let src = output.as_bytes().as_ptr();
    let len = output.as_bytes().len();
    let len_c_int = len as cty::c_int;
    if len_c_int <= max_len - 1 {
        unsafe {
            std::ptr::copy(src, buf as *mut u8, len);
            (*buf.offset(len as isize)) = 0;
        }
        len_c_int
    } else {
        -1000
    }
}

pub(crate) fn serialize<P: Pairing>(
    public_inputs: Vec<P::ScalarField>,
    proof: Proof<P>,
) -> anyhow::Result<String> {
    let mut proof_vec = Vec::new();
    proof
        .serialize_compressed(&mut proof_vec)
        .expect("failed to serialize proof");

    let output = ProvingOutput {
        public_inputs: public_inputs.iter().map(|v| v.to_string()).collect(),
        proof: hex::encode(&proof_vec),
    };
    let output = serde_json::to_string(&output).expect("failed to serialize to output");
    Ok(output)
}

#[cfg(test)]
mod utils_test {
    use crate::utils::{do_prove, load_context, parse_proving_input, serialize};
    use itertools::Itertools;

    #[test]
    fn test_parse_proving_input() {
        let json_str = r#"
            {
                "key1": ["123", "456"],
                "key2": [
                    "5841544268561861499519250994748571",
                    "282086110796185156675799806248152448"
                ]
            }
        "#;

        let parsed_input = parse_proving_input(json_str);
        assert!(parsed_input.is_ok());
        let parsed_input = parsed_input.unwrap();
        let v1 = parsed_input["key1"]
            .iter()
            .map(|n| n.to_str_radix(10))
            .join(",");

        let v2 = parsed_input["key2"]
            .iter()
            .map(|n| n.to_str_radix(10))
            .join(",");

        assert_eq!("123,456", v1);
        assert_eq!(
            "5841544268561861499519250994748571,282086110796185156675799806248152448",
            v2
        );
    }

    #[test]
    fn test_complete_flow() {
        let ctx = load_context(
            "../data-files/guardianhash.wasm",
            "../data-files/guardianhash.r1cs",
            "../data-files/guardianhash_0001.zkey",
        );
        assert!(ctx.is_ok());
        let ctx = ctx.unwrap();
        let res = do_prove(&ctx, "{\"jwt\": [\"101\", \"121\", \"74\", \"104\", \"98\", \"71\", \"99\", \"105\", \"79\", \"105\", \"74\", \"83\", \"85\", \"122\", \"73\", \"49\", \"78\", \"105\", \"73\", \"115\", \"73\", \"110\", \"82\", \"53\", \"99\", \"67\", \"73\", \"54\", \"73\", \"107\", \"112\", \"88\", \"86\", \"67\", \"74\", \"57\", \"46\", \"101\", \"121\", \"74\", \"122\", \"100\", \"87\", \"73\", \"105\", \"79\", \"105\", \"73\", \"120\", \"77\", \"106\", \"77\", \"48\", \"78\", \"84\", \"89\", \"51\", \"79\", \"68\", \"107\", \"119\", \"73\", \"105\", \"119\", \"105\", \"98\", \"109\", \"70\", \"116\", \"90\", \"83\", \"73\", \"54\", \"73\", \"107\", \"112\", \"118\", \"97\", \"71\", \"52\", \"103\", \"82\", \"71\", \"57\", \"108\", \"73\", \"105\", \"119\", \"105\", \"89\", \"87\", \"82\", \"116\", \"97\", \"87\", \"52\", \"105\", \"79\", \"110\", \"82\", \"121\", \"100\", \"87\", \"85\", \"115\", \"73\", \"109\", \"108\", \"104\", \"100\", \"67\", \"73\", \"54\", \"77\", \"84\", \"85\", \"120\", \"78\", \"106\", \"73\", \"122\", \"79\", \"84\", \"65\", \"121\", \"77\", \"110\", \"48\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\", \"0\"], \"signature\": [\"136066698678378650066472176144548241\", \"1800384327008418817146654168653894619\", \"2574524618487272827404567912127994032\", \"1572551955913018780280859127440201929\", \"1890564471282023685923539663639306374\", \"1866512077014082189748713566387377304\", \"2222710341065048773940709188556978891\", \"840541024972195344747634213092278743\", \"330476852732802730001627869075985501\", \"1294859790995514400195378924750900104\", \"1136356663482937321790125666232087630\", \"2501709109099362467808413692918409573\", \"1776875315524942066973947221991971257\", \"913872260108236275630951234884908773\", \"1608150223070592825745836511435000141\", \"1583177297555626922284372616305354634\", \"1063982966443379747600844439851650\"], \"pubkey\": [\"5841544268561861499519250994748571\", \"282086110796185156675799806248152448\", \"2181169572700087019903500222780233598\", \"1322589976114836556068768894837633649\", \"1794113848426178665483863008905364300\", \"543380795324313410170505147425740531\", \"1493214249295981343844955353860051664\", \"2171199579242924905862250512208697455\", \"1395394319132308840130123038054629304\", \"1562009664380263536909338779810969578\", \"1594567849407226969396248621216777848\", \"2058356264851095114515728757906168363\", \"836769104848661443299826291369000556\", \"1779001964758400339025173335511101862\", \"2544058187525854999124570613534759403\", \"424565350689075956046563544271353450\", \"3799511822475913352444008446631779\"], \"salt\": [\"97\", \"54\", \"55\", \"55\", \"57\", \"57\", \"57\", \"51\", \"57\", \"54\", \"100\", \"99\", \"52\", \"57\", \"97\", \"50\", \"56\", \"97\", \"100\", \"54\", \"99\", \"57\", \"99\", \"50\", \"52\", \"50\", \"55\", \"49\", \"57\", \"98\", \"98\", \"51\"]}");
        assert!(res.is_ok());
        let (pub_inputs, proof) = res.unwrap();
        let output = serialize(pub_inputs, proof);
        println!("{}", output.unwrap());
    }
}
