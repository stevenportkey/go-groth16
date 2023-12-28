use crate::dto::ProvingOutput;
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
use ark_std::iterable::Iterable;
// use eyre::ContextCompat;
use ark_ff::PrimeField;


pub struct ProvingContext<P: Pairing> {
    pub(crate) cfg: CircomConfig<P>,
    pub(crate) pk: ProvingKey<P>,
}

impl<P: Pairing> ProvingContext<P> {
    pub(crate) fn verifying_key_in_hex(&self) -> String {
        let mut vk = Vec::new();
        self.pk.vk.serialize_compressed(&mut vk).expect("failed to serialize the verifying key");
        hex::encode(vk)
    }
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

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl Display for crate::utils::ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ParseError: {}", self.message)
    }
}

impl std::error::Error for crate::utils::ParseError {}

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
    vk: &str,
    proving_output: &str,
) -> anyhow::Result<bool> {
    let vk = hex::decode(vk).context("failed to decode VerifyingKey")?;
    let proving_output: ProvingOutput = serde_json::from_str(proving_output).context("failed to decode ProvingOutput")?;
    let proof = hex::decode(proving_output.proof).context("failed to decode proof")?;
    let inputs = decode_public_input_array::<P>(proving_output.public_inputs)?;
    do_verify0::<P>(vk, proof, inputs)
}

pub(crate) fn do_verify0<P: Pairing>(
    vk: Vec<u8>,
    proof: Vec<u8>,
    inputs: Vec<P::ScalarField>,
) -> anyhow::Result<bool> {
    let vk = VerifyingKey::<P>::deserialize_compressed(&*vk)?;
    let pvk = prepare_verifying_key(&vk);

    let proof = Proof::deserialize_compressed(&*proof)?;
    let res = Groth16::<P>::verify_with_processed_vk(&pvk, inputs.as_slice(), &proof)?;
    Ok(res)
}

pub(crate) fn decode_public_input_array<P: Pairing>(public_inputs: Vec<String>) -> anyhow::Result<Vec<P::ScalarField>> {
    let inputs: Vec<_> = public_inputs.iter().enumerate().map(|(i, s)| {
        let value = BigInt::from_str_radix(s, 10).map_err(|_| ParseError {
            message: format!("{}: {}", i, s)
        })?;
        let (_, bytes) = value.to_bytes_be();
        let scalar = P::ScalarField::from_be_bytes_mod_order(bytes.as_slice());
        Ok::<<P as Pairing>::ScalarField, ParseError>(scalar)
    }).collect();
    // let err = inputs.iter().find(|input| {
    //     if input.is_err() {
    //         println!("{:?}", input.as_ref().clone().err().unwrap());
    //     }
    //     input.is_err()
    // });
    // if err.is_some() {
    //     println!("{:?}", err.unwrap().as_ref().clone().err().unwrap());
    // }
    let _ = match inputs.iter().any(|value| value.is_err()) {
        true => { Ok(0) }
        false => { Err(ParseError { message: "parse error".to_string() }) }
    }.context("failed to parse input");

    let inputs = inputs.iter().map(|value| value.as_ref().unwrap().clone()).collect();
    Ok(inputs)
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
        println!("required length is {}", len_c_int);
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
    use ark_bn254::Bn254;
    use crate::utils::{do_prove, do_verify, load_context, parse_proving_input, serialize};
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

    #[test]
    fn test_export_vk() {
        let ctx = load_context(
            "../data-files/guardianhash.wasm",
            "../data-files/guardianhash.r1cs",
            "../data-files/guardianhash_0001.zkey",
        );
        assert!(ctx.is_ok());
        let vk = ctx.unwrap().verifying_key_in_hex();
        println!("{}", vk);
    }

    #[test]
    fn test_verify() {
        let proving_output = "{\"public_inputs\":[\"95\",\"49\",\"58\",\"6\",\"195\",\"116\",\"113\",\"221\",\"31\",\"181\",\"224\",\"199\",\"58\",\"220\",\"110\",\"223\",\"30\",\"242\",\"192\",\"153\",\"210\",\"191\",\"245\",\"71\",\"155\",\"73\",\"215\",\"220\",\"204\",\"102\",\"42\",\"108\",\"5841544268561861499519250994748571\",\"282086110796185156675799806248152448\",\"2181169572700087019903500222780233598\",\"1322589976114836556068768894837633649\",\"1794113848426178665483863008905364300\",\"543380795324313410170505147425740531\",\"1493214249295981343844955353860051664\",\"2171199579242924905862250512208697455\",\"1395394319132308840130123038054629304\",\"1562009664380263536909338779810969578\",\"1594567849407226969396248621216777848\",\"2058356264851095114515728757906168363\",\"836769104848661443299826291369000556\",\"1779001964758400339025173335511101862\",\"2544058187525854999124570613534759403\",\"424565350689075956046563544271353450\",\"3799511822475913352444008446631779\",\"97\",\"54\",\"55\",\"55\",\"57\",\"57\",\"57\",\"51\",\"57\",\"54\",\"100\",\"99\",\"52\",\"57\",\"97\",\"50\",\"56\",\"97\",\"100\",\"54\",\"99\",\"57\",\"99\",\"50\",\"52\",\"50\",\"55\",\"49\",\"57\",\"98\",\"98\",\"51\"],\"proof\":\"aaf87197971c2fbba7550f621add868c1f5c65ef2d9e11e66eeb93fa9192c59f4759088dac8abfcc5a9443b205b2cba11659836d1fe76214f28050e0b565511da494af12152309a16eb3bd862cf2ff43dc80497f2c1a2aa8e53db48a6bb69c84756f0ed1c534c0c2e926fd3dadcfa5f433f765773b885f207a99635516c79d9e\"}\n";
        let vk = "987eb6f620cbd00941204ec4f6a81a46419373a821c8ffd9affca1291900631ffeca146164a8f8cada7dd266805f0f0d406158686ebab25caf020ec28a02c6073dbbf2228db69a59b85c97eced983f4189e8ecb6397838d0bea80eb50af98800edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19c9809249c6849563b6de34d0b1e119676bf904cd536b6df9a91eb2b788c6e02b553d1ce7c10bc6c904176abbae5f92ea87217214f849f84b4c49b1ed660576ac52000000000000009c151f6e98a6eeba3e77eb083a5530c7f6dc57f73ee5c4cb2607328a0786ac877763c5ed08a9ca3a22be657458d0abe287e1e90eeb090eafdaa015fe5b8fd3af5daaa2fdb341443764c35cdd224dea08328d679f1f3c51a924b8f2169c967f0cd8294c5a3eee3658a7ea37d03dabc896166e7511bd358b1103b954eb40b6322f30e5860d9355842fc24ecc6d9d552de4fd96b94b10a1637acaa345856c9b99965fef99948868fcf9371dade7eb884332e406b862f2ad3c707000dfc00afa759776504a0be7d95f263fc3eeb05182fe13e87a454de725234f00b09f066e67d4988b9cec1068f188de4b159c67e9179122a24f7cbb08a60e8d85d1f14b30cda59718097eb24e6848b5259007f899c6c9cfd74a6f80d83012ba9d8d81cf749b9f94c3678ff9c27b3819790a8f34aac6f7a1dcb8c64b0849e556907cf9b8bb03c814a83342e1a1ec91cfc09040cdac4860e4bf58eab54cf6683915385273bee047043fff7233f542b5d2e7f253441c5510feb73d6556f4e82cec7fa1aae962928590a89fd7e4ab8c0acec7e987934ccc82613cf27cc7877d4ffba7292964c5196b8b3c59d35f65bef53f79d8859d885c7812f3990c178d11972915db542a4e5491843462343bd1751c0e20600fadec3452bceabb40b16cbf690ec08d3136fc531901f1794a95c305f59c5eb0f08020133677631e6c63eba360e8210e0900011d198a33d592db0b3d1ca7de038df1c7beefc126fd54edde961b5ccacfd0e7c6a63a1f2541ab8a0f4b1a5fef017c61db38c07ce6293c60444833a3d3f559388322440da9d8023d27b01352484ecb3b584234aea7c4864c2a9636281a780f4ca72a88130e313f20ad8d1be5d7fcb0d8c3f19a7947e175276e9e4fdf2662dd69d40707a13dc6fbfa476630aed4d4765c16ed498193c13f101b7bc026c8cdf0e1e33224a72f49b1838a9faae596b3a5000f58a853c4357ec6e513c7c72aed53443b3f2799ebea44e164adc686e984e421bd2658aa7e2dcaed5e8f7679e49135645ba764036343868a918febf74f0582a67a3ac12fe45054be22897d1032ae3425d7957984eea1f42137dcb6e61b2bd0fcd999f70a1dda03eb5ba491b7d5c728a5d5ab0dad5170f3f89fc588a96fb9e352630ef658612b90cd70cef388c901e500567fd49a788657ef607b53faeeb3f2f3044ac411d74383312c3ec16d34c60d7380432791c7a9596772efa9f9488af5628731110da0ac5981381e2c50718e772354f1b7886450951b83e94b65218b12f49c33fec3fc5da0adf91180ac471841b00245200d7a7d36022bd3436e441ee98cfa2e15478dbdd484ddb8c75b5346a48b3005c517ccdf78088e0e205bb0ac382782934f64d634902926027e489ee6aced666e6623f2e13d7bddb461c0390afab9b66d018a190f4acc83e53b6b43cdd6149fe704875f4a251912f5ebbe60213893498d25b497b576f97a2ba9abbfa2f882cc3da1088bfb7e0681cc3df70b4f4be3101ac68ee75db080c60b1489bc74b83cd0b45697fffa8f54a41231e46f48fd240ded208cf24128d1ff5071085574d2488c517c9011d3940924f7ac57a4d9123c7a9ae81592f9e707cb8353476944895c52c7d483bfa83e6f242b867eda6f2f4e483c6028c5ddd82f61b6e96a9d841a176ca7691ee06f99bb78565dd1efc2962ccf825acc22d5a1af5c72a365e60f443c0307570e1ee665d20803ade104d1a982dace277f0ada2bbae8ded842bab4c80d2033b8935ccfd3f6a2eb4543b8a141eabcc11ce6ff080e88fd77794aabfeaf4b649c6687e30e943e1532ba877ba8ec58fcf83933600de41b1d39d697f0cdeb0580bdf72004d57cb34375c3e93ed9a6c8cd57fc6505e72898e0019de2273aa3d12bef1b82f246a5fbf87e1ad673679ebc8d43927221f43b9be4f5fdd3c295392e61d8b08e7d15ee1a673a72b2f7d550bcd790dafbb0abf05afd53269e272f77eac01045a9d7a57591ee749e32e503beeb087d85d422d8b20d3bd33ea81b69cbf948413113441fc46ded8012287fb616c50ce0644c26ad260700c3a84090f5012d55640321f863f611e32c8c86323b6447e9667302fcea4bf4a7295ad8a780e8556200f386e136cbd88d2c4c0f55bece8ec448ec97bdcb228d966b1ae1d6b90fd04d151827d23192a81ba92ecc6497ae4efe29816c9d3ff6f59c86790f9d2cef3c6512df054cd6b592f8b22ab99c6feec5b5769854628e982696d181edbd7af51c742fe0ad556719dc5d058af8323d5ad2e1ced663f6d651e7270c48cb754fc8c7dc54bea6ea5066168d83a1dbaec797269e2a27854b29efadca48f45810a5981a9487c3963e08aaa9c753625d6e1bf7e0c7715b742b499eec6024278661d81e3966c34b808958cd41dd4231b73a7c83b53b7952a7662ee23fc992dbe1762e407599e967a2a0dc4a1460b2696271c18bf9a4a2ff81033d091c3b5dcf159355f5d80b2f2416881f87f36250f8b698c54ed578ddba66ea2e843139f53bda78227f94e128bbacf2a55aca6aa45c57c1b8d37f22bdf1f43b33416e10154aaeb5b066197c7a10a0aa1ada15d121772458db8a2cceb2246f1989ae8034b0834ba046cc0b3b2aeb2e5f1a4509689e6f90247ba522a7750ec45dcfb8ccd6cbb96914094e6d22593c94d45a8431e43a878190cb76172c8352b1498210804dfd17d90c863f4e2f38ad834d5ba68786bcb8a6f23620f80cfda6a0897223c2e8cc65c816db7a183e8ed9a201f5052c550006e73b82e84b5aa7c68a03963589bbfa7211ebb94eb6ea67f0afa8c377537392cff65e6d387c706a132061e951a618e86fde840418dfb530c78fc62bb5f11bd7d02de011108af6c5292650aa5defc8681c6e665d64765a4b361e54beda792c256126fa7d20bd8d1196dbd8df7280de28df371c71676ff6119d858dfe4d89958facd30a83f85cbbc1f5e0f033e5bec0cbbf5776b6b5dc042c02160d15ccb8817ca29c1de85c9bd0c6a9324f6e841db10381d6c37e984c90f6ec03c21ae7fc923c1d5d4b170715e5b8b6c3967e747f32023130b3d0cb942aff490603bb27f75c35974824fd0d1576e89107b94f389aa7fa4208f85b6aac2236ad128df3e1462a58df316b940a3eaf5abfd60b982bfa66eb82cafe400b2c1691a109ec262956d6ae8efea99d744494919388555c3b618e32da802106f772084b6d991a4c936e43c09aea0f94e58faeba8443a4dec1b4e614409c158d60ac30d8f51b457eba9976cf41f808d9c6e354d8dd96ecabc688495ad7a1527c14c3bac4ff0c44d78d865fff4458e1ba692519067646a05f7cd000ac2713da8533fd2e1a7b2742f306019c0ff40dd7977af2955491b38a968535d45800fe4b1de5dd1fd57d841ef0aa6de5399ebb62890442be384064521e0714f1ce79d0ddb11d9a653bd118e9a1fdbd65b537c72073764441c403a9970bdaf492df2a3467f981b1f1cb9c8176edb4360a812072f49826c90c0bb9d6f48a9fe26b3801acd4017522614f2fa45921dc29ba4eed20a5fee59f8ea036eb378ccd88f528dd568b04444a8987ac0285fe133836cc09f79277687a4cd07768573e607e5fdd249ff663da3f59d9bcaf1aca98a2b2f7eb662b2554137368f9d44865a4a6ef4f59ff8054e3ee984a48820a02793050f9a638be35964963ac8efb847b056e185f548c88c59b282d27650b";
        let res = do_verify::<Bn254>(vk, proving_output);
        assert!(res.is_ok());
        assert!(res.unwrap());
    }
}
