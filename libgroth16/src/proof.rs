use ark_std::str::FromStr;
use ark_ec::{
    models::CurveConfig,
    pairing::Pairing,
};
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger256, fields::{Field, PrimeField}, QuadExtConfig};
use ark_groth16::Proof;
use std::marker::PhantomData;
use num_bigint::BigUint;
use ark_ec::{
    bn,
    bn::{Bn, BnConfig, TwistType},
};

use ark_bn254::{Bn254, G1Projective, G2Projective, Fq, Fq2};
use num_traits::Zero;

use serde_json::{Value, json};

#[derive(Debug)]
pub(crate) struct RapidSnarkProof {
    pub(crate) pi_a: Vec<Fq>,
    pub(crate) pi_b: Vec<Vec<Fq>>,
    pub(crate) pi_c: Vec<Fq>,
    pub(crate) protocol: String,
}


impl Serialize for RapidSnarkProof
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
    {
        let pi_a: Vec<String> = self.pi_a.iter().map(|x| x.to_string()).collect();
        let pi_b: Vec<Vec<String>> = self.pi_b.iter().map(|inner| inner.iter().map(|x| {
            match x.is_zero() {
                true => "0".to_string(),
                _ => x.to_string()
            }
        }).collect()).collect();
        let pi_c: Vec<String> = self.pi_c.iter().map(|x| x.to_string()).collect();

        // Convert to JSON using serde_json::json!
        let json = json!({
            "pi_a": pi_a,
            "pi_b": pi_b,
            "pi_c": pi_c,
            "protocol": self.protocol
        });

        serializer.serialize_newtype_struct("RapidSnarkProof", &json)
    }
}

impl<'de> Deserialize<'de> for RapidSnarkProof
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
    // <<P as BnConfig>::Fq as FromStr>::Err: std::fmt::Display
    {
        let json: Value = serde::Deserialize::deserialize(deserializer)?;
        let pi_a: Vec<Fq> = json["pi_a"].as_array()
            .ok_or_else(|| serde::de::Error::custom("Expected pi_a to be an array"))?
            .iter()
            .map(|x| x.as_str().ok_or_else(|| serde::de::Error::custom("Expected string"))
                .and_then(|str| str.parse::<Fq>().map_err(|_| serde::de::Error::custom("Not valid prime field element"))))
            .collect::<Result<_, _>>()?;

        let pi_b: Vec<Vec<Fq>> = json["pi_b"].as_array()
            .ok_or_else(|| serde::de::Error::custom("Expected pi_b to be an array of arrays"))?
            .iter()
            .map(|inner| inner.as_array().ok_or_else(|| serde::de::Error::custom("Expected inner array"))
                .and_then(|inner_vec| inner_vec.iter()
                    .map(|x| x.as_str().ok_or_else(|| serde::de::Error::custom("Expected string"))
                        .and_then(|str| str.parse::<Fq>().map_err(|_| serde::de::Error::custom("Not valid prime field element"))))
                    .collect::<Result<_, _>>()))
            .collect::<Result<_, _>>()?;

        let pi_c: Vec<Fq> = json["pi_c"].as_array()
            .ok_or_else(|| serde::de::Error::custom("Expected pi_c to be an array"))?
            .iter()
            .map(|x| x.as_str().ok_or_else(|| serde::de::Error::custom("Expected string"))
                .and_then(|str| str.parse::<Fq>().map_err(|_| serde::de::Error::custom("Not valid prime field element"))))
            .collect::<Result<_, _>>()?;

        let protocol: String = json["protocol"].as_str()
            .ok_or_else(|| serde::de::Error::custom("Expected protocol to be a string"))
            .map(str::to_owned)?;

        Ok(RapidSnarkProof {
            pi_a,
            pi_b,
            pi_c,
            protocol,
        })
    }
}


impl From<Proof<Bn254>> for RapidSnarkProof {
    fn from(proof: Proof<Bn254>) -> Self {
        let a = G1Projective::from(proof.a);
        let b = G2Projective::from(proof.b);
        let c = G1Projective::from(proof.c);
        let pi_a = vec![a.x, a.y, a.z];
        let pi_b = vec![vec![b.x.c0, b.x.c1], vec![b.y.c0, b.y.c1], vec![b.z.c0, b.z.c1]];
        let pi_c = vec![c.x, c.y, c.z];
        Self {
            pi_a,
            pi_b,
            pi_c,
            protocol: "groth16".to_string(),
        }
    }
}

impl Into<Proof<Bn254>> for RapidSnarkProof {
    fn into(self) -> Proof<Bn254> {
        Proof::<Bn254> {
            a: G1Projective {
                x: self.pi_a[0].clone(),
                y: self.pi_a[1].clone(),
                z: self.pi_a[2].clone(),
            }.into_affine(),
            b: G2Projective {
                x: Fq2::new(self.pi_b[0][0].clone(), self.pi_b[0][1].clone()),
                y: Fq2::new(self.pi_b[1][0].clone(), self.pi_b[1][1].clone()),
                z: Fq2::new(self.pi_b[2][0].clone(), self.pi_b[2][1].clone()),
            }.into_affine(),
            c: G1Projective {
                x: self.pi_c[0].clone(),
                y: self.pi_c[1].clone(),
                z: self.pi_c[2].clone(),
            }.into_affine(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use crate::proof::BnConfig;
    use ark_bn254::Bn254;
    use ark_groth16::{Groth16, Proof};
    use ark_serialize::CanonicalDeserialize;
    use crate::proof::RapidSnarkProof;
    // use crate::proof::RapidSnarkProof1;
    use ark_bn254::{Config, G1Projective, G2Projective, Fr, Fq, Fq2};
    use ark_circom::read_zkey;
    use ark_ec::bn::Bn;
    use ark_ec::CurveGroup;
    use rand::thread_rng;
    use ark_snark::SNARK;
    use ark_serialize::CanonicalSerialize;

    //
    // #[test]
    // fn test_conversion_of_proof() {
    //     let proof = "08e444240a2ae1d2f44827e7596468d21d453b562bd97cf80faa6a5c1d0226a7e054699d7c09c74ec974110222f95fff8a7cfbef71198379b68707fc668c8626b48c21b3f72c734b9ce1c392be430d4109623a43149271f6a1d2cf0401e33d1cfb7308b3603b902f76c80f432d7635f8a4bb509303846d49bc5766bd4b6e062d";
    //
    //     let proof = hex::decode(proof).unwrap();
    //     // let proof: Proof<Bn254> = ark_serialize::deser(&proof).unwrap();
    //
    //     let proof = Proof::<Bn254>::deserialize_compressed(&*proof).unwrap();
    //
    //     let proof = RapidSnarkProof::<Config>::from(proof);
    //     // let proof: Proof<Bn254> = proof.into();
    //     // println!("{:?}", proof);
    //     println!("1234");
    // }


    #[test]
    fn test_simple() {
        let x = "5238559682216240640667572217788019090970556999702137143095079589574723338025".parse::<<ark_bn254::Config as BnConfig>::Fp>();
        println!("{:?}", x.expect("").to_string());
    }

    #[test]
    fn test_parse() {
        let json_str = r#"
            {
                "pi_a": [
                    "10628318265912327242199010897794312944436552392434691864126148839210117788175",
                    "5238559682216240640667572217788019090970556999702137143095079589574723338025",
                    "1"
                ],
                "pi_b": [
                    [
                        "5756044698056741746054834432264228922186028479650944688672181256550560507351",
                        "17458451018681680750438704746976753952868662837037853254203586950377769762566"
                    ],
                    [
                        "11700504957796258181916761004927102020057425671112067042269967580217527755162",
                        "15228416592230967633425295803603720441763485589812678386823840332786513862827"
                    ],
                    [
                        "1",
                        "0"
                    ]
                ],
                "pi_c": [
                    "881544555553568886419433261972576118307241699999655569969967193195669487866",
                    "13997891198868562058647816998824321598844351894512846699626881040906864628201",
                    "1"
                ],
                "protocol": "groth16"
            }
        "#;

        let proof: RapidSnarkProof<Config> = serde_json::from_str(json_str).expect("Failed to deserialize");

        let proof = Proof::<Bn254> {
            a: G1Projective {
                x: proof.pi_a[0].clone(),
                y: proof.pi_a[1].clone(),
                z: proof.pi_a[2].clone(),
            }.into_affine(),
            b: G2Projective {
                x: Fq2::new(proof.pi_b[0][0].clone(), proof.pi_b[0][1].clone()),
                y: Fq2::new(proof.pi_b[1][0].clone(), proof.pi_b[1][1].clone()),
                z: Fq2::new(proof.pi_b[2][0].clone(), proof.pi_b[2][1].clone()),
            }.into_affine(),
            c: G1Projective {
                x: proof.pi_c[0].clone(),
                y: proof.pi_c[1].clone(),
                z: proof.pi_c[2].clone(),
            }.into_affine(),
        };

        // let parsed_json: RapidSnarkProof<Config> =
        //     serde_json::from_str(json_str).expect("Failed to parse JSON");
        println!("abc");
    }

    #[test]
    fn test_Fp2() {
        let a =
            <ark_bn254::Config as BnConfig>::Fp::from(1u64);
        let b = <ark_bn254::Config as BnConfig>::Fp::from(2u64);
        a.to_string();
        println!("{:?}", a.to_string());
    }
}