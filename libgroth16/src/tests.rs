#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;

    use num_bigint::BigInt;
    use rand::thread_rng;

    use std::fs::File;

    fn dec(hex_string: &str) -> BigInt {
        BigInt::parse_bytes(hex_string.to_string().as_bytes(), 10).unwrap()
    }

    struct Input {
        pub jwt: Vec<BigInt>,
        pub signature: Vec<BigInt>,
        pub pubkey: Vec<BigInt>,
        pub salt: Vec<BigInt>,
    }

    fn prepare_input() -> Input {
        let jwt = [
            101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115,
            73, 110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74,
            122, 100, 87, 73, 105, 79, 105, 73, 120, 77, 106, 77, 48, 78, 84, 89, 51, 79, 68, 107,
            119, 73, 105, 119, 105, 98, 109, 70, 116, 90, 83, 73, 54, 73, 107, 112, 118, 97, 71,
            52, 103, 82, 71, 57, 108, 73, 105, 119, 105, 89, 87, 82, 116, 97, 87, 52, 105, 79, 110,
            82, 121, 100, 87, 85, 115, 73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 85, 120, 78,
            106, 73, 122, 79, 84, 65, 121, 77, 110, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
        .iter()
        .map(|v| BigInt::from(v.clone()))
        .collect();
        let salt = [
            97, 54, 55, 55, 57, 57, 57, 51, 57, 54, 100, 99, 52, 57, 97, 50, 56, 97, 100, 54, 99,
            57, 99, 50, 52, 50, 55, 49, 57, 98, 98, 51,
        ]
        .iter()
        .map(|v| BigInt::from(v.clone()))
        .collect();
        let signature: Vec<BigInt> = [
            "136066698678378650066472176144548241",
            "1800384327008418817146654168653894619",
            "2574524618487272827404567912127994032",
            "1572551955913018780280859127440201929",
            "1890564471282023685923539663639306374",
            "1866512077014082189748713566387377304",
            "2222710341065048773940709188556978891",
            "840541024972195344747634213092278743",
            "330476852732802730001627869075985501",
            "1294859790995514400195378924750900104",
            "1136356663482937321790125666232087630",
            "2501709109099362467808413692918409573",
            "1776875315524942066973947221991971257",
            "913872260108236275630951234884908773",
            "1608150223070592825745836511435000141",
            "1583177297555626922284372616305354634",
            "1063982966443379747600844439851650",
        ]
        .iter()
        .map(|v| dec(v.clone()))
        .collect();
        let pubkey: Vec<BigInt> = [
            "5841544268561861499519250994748571",
            "282086110796185156675799806248152448",
            "2181169572700087019903500222780233598",
            "1322589976114836556068768894837633649",
            "1794113848426178665483863008905364300",
            "543380795324313410170505147425740531",
            "1493214249295981343844955353860051664",
            "2171199579242924905862250512208697455",
            "1395394319132308840130123038054629304",
            "1562009664380263536909338779810969578",
            "1594567849407226969396248621216777848",
            "2058356264851095114515728757906168363",
            "836769104848661443299826291369000556",
            "1779001964758400339025173335511101862",
            "2544058187525854999124570613534759403",
            "424565350689075956046563544271353450",
            "3799511822475913352444008446631779",
        ]
        .iter()
        .map(|v| dec(v.clone()))
        .collect();

        Input {
            jwt,
            signature,
            pubkey,
            salt,
        }
    }

    #[test]
    fn test_with_zkey() {
        let cfg = CircomConfig::<Bn254>::new(
            "../data-files/guardianhash.wasm", // md5(bf777bdc0b7ea32c5c484e54de2b75dc)
            "../data-files/guardianhash.r1cs", // md5(01f743ccdf2637c9cebca0b8799c1043)
        )
        .unwrap();

        let input_values = prepare_input();
        let mut builder = CircomBuilder::new(cfg);

        for v in input_values.jwt {
            builder.push_input("jwt", v);
        }
        for v in input_values.salt {
            builder.push_input("salt", v);
        }
        for v in input_values.pubkey {
            builder.push_input("pubkey", v);
        }
        for v in input_values.signature {
            builder.push_input("signature", v);
        }
        let circom = builder.build().unwrap();

        let inputs = circom.get_public_inputs().unwrap();
        println!("{}", inputs.len());
        for (i, input) in inputs.iter().enumerate() {
            let mut vec = Vec::new();
            input.serialize_compressed(&mut vec);
            println!("in{}: {}, ", i, hex::encode(vec));
        }

        let mut rng = thread_rng();
        let mut key_file = File::open("../data-files/guardianhash_0001.zkey").unwrap(); // md5(81fc879f0d8bc92329c5c79e7584e9cb)
        let (params, _) = read_zkey(&mut key_file).unwrap();

        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        circom.clone().generate_constraints(cs.clone()).unwrap();
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);

        let proof = Groth16::<Bn254, CircomReduction>::prove(&params, circom, &mut rng).unwrap();

        // Check that the proof is valid
        let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();
        let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs).unwrap();

        assert!(verified);
    }

    use std::collections::HashMap;

    #[test]
    fn test_serde_of_hashmap() {
        let json_str = r#"
            {
                "key1": ["value1", "value2"],
                "key2": ["value3", "value4"]
            }
        "#;

        let parsed_json: HashMap<String, Vec<String>> =
            serde_json::from_str(json_str).expect("Failed to parse JSON");

        println!("{:?}", parsed_json);
    }
}
