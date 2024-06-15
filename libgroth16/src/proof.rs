use ark_std::str::FromStr;
use ark_ec::{
    models::CurveConfig,
    pairing::Pairing,
};
use serde::{Deserialize, Serialize};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger256, fields::{Field, PrimeField, Fp2}, QuadExtConfig};
use ark_groth16::Proof;
use std::marker::PhantomData;
use num_bigint::BigUint;
use ark_ec::{
    bn,
    bn::{Bn, BnConfig, TwistType},
};

use serde_json::{Value, json};


// Assuming that `P::Fp` implements `ToString` and `std::str::FromStr`
#[derive(Debug)]
pub(crate) struct RapidSnarkProof<P: BnConfig> {
    pub(crate) pi_a: Vec<P::Fp>,
    pub(crate) pi_b: Vec<Vec<P::Fp>>,
    pub(crate) pi_c: Vec<P::Fp>,
    pub(crate) protocol: String,
    // #[serde(skip)]
    // _phantom: PhantomData<P>,
}

//
// impl<P: BnConfig> Serialize for RapidSnarkProof<P>
//     where
//         P::Fp: ToString,
// {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//         where
//             S: serde::Serializer,
//     {
//         let pi_a: Vec<String> = self.pi_a.iter().map(|x| x.to_string()).collect();
//         let pi_b: Vec<Vec<String>> = self.pi_b.iter().map(|inner| inner.iter().map(|x| x.to_string()).collect()).collect();
//         let pi_c: Vec<String> = self.pi_c.iter().map(|x| x.to_string()).collect();
//
//         // Convert to JSON using serde_json::json!
//         let json = json!({
//             "pi_a": pi_a,
//             "pi_b": pi_b,
//             "pi_c": pi_c,
//             "protocol": self.protocol
//         });
//
//         serializer.serialize_newtype_struct("RapidSnarkProof", &json)
//     }
// }
//
impl<'de, P: BnConfig> Deserialize<'de> for RapidSnarkProof<P>
    where
        P::Fp: std::str::FromStr,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
    // <<P as BnConfig>::Fp as FromStr>::Err: std::fmt::Display
    {
        let json: Value = serde::Deserialize::deserialize(deserializer)?;
        let pi_a: Vec<P::Fp> = json["pi_a"].as_array()
            .ok_or_else(|| serde::de::Error::custom("Expected pi_a to be an array"))?
            .iter()
            .map(|x| x.as_str().ok_or_else(|| serde::de::Error::custom("Expected string"))
                .and_then(|str| str.parse::<P::Fp>().map_err(|_| serde::de::Error::custom("Not valid prime string"))))
            .collect::<Result<_, _>>()?;

        let pi_b: Vec<Vec<P::Fp>> = json["pi_b"].as_array()
            .ok_or_else(|| serde::de::Error::custom("Expected pi_b to be an array of arrays"))?
            .iter()
            .map(|inner| inner.as_array().ok_or_else(|| serde::de::Error::custom("Expected inner array"))
                .and_then(|inner_vec| inner_vec.iter()
                    .map(|x| x.as_str().ok_or_else(|| serde::de::Error::custom("Expected string"))
                        .and_then(|str| str.parse::<P::Fp>().map_err(|_| serde::de::Error::custom("Not valid prime string"))))
                    .collect::<Result<_, _>>()))
            .collect::<Result<_, _>>()?;

        let pi_c: Vec<P::Fp> = json["pi_c"].as_array()
            .ok_or_else(|| serde::de::Error::custom("Expected pi_c to be an array"))?
            .iter()
            .map(|x| x.as_str().ok_or_else(|| serde::de::Error::custom("Expected string"))
                .and_then(|str| str.parse::<P::Fp>().map_err(|_| serde::de::Error::custom("Not valid prime string"))))
            .collect::<Result<_, _>>()?;

        let protocol: String = json["protocol"].as_str()
            .ok_or_else(|| serde::de::Error::custom("Expected protocol to be a string"))
            .map(str::to_owned)?;

        Ok(RapidSnarkProof {
            pi_a,
            pi_b,
            pi_c,
            protocol,
            // _phantom: PhantomData
        })
    }
}


// impl<P: BnConfig> From<Proof<Bn<P>>> for RapidSnarkProof<P> {
//     // type G2Field = Fp2<P::Fp2Config>;
//     fn from(proof: Proof<Bn<P>>) -> Self {
//         let xx: Vec<_> = proof.a.x().unwrap().to_base_prime_field_elements().collect();
//         let pi_a = vec![
//             proof.a.x().unwrap().to_base_prime_field_elements().next().expect("must have").to_string(),
//             proof.a.y().unwrap().to_base_prime_field_elements().next().expect("must have").to_string(),
//             "1".to_string(),
//         ];
//         let pi_b_x = proof.b.x().unwrap().to_base_prime_field_elements().map(|v| v.to_string()).collect();
//         let pi_b_y = proof.b.y().unwrap().to_base_prime_field_elements().map(|v| v.to_string()).collect();
//         let pi_b = vec![
//             pi_b_x,
//             pi_b_y,
//             vec!["1".to_string(), "0".to_string()],
//         ];
//         let pi_c = vec![
//             proof.c.x().unwrap().to_base_prime_field_elements().next().expect("must have").to_string(),
//             proof.c.y().unwrap().to_base_prime_field_elements().next().expect("must have").to_string(),
//             "1".to_string(),
//         ];
//         Self {
//             pi_a,
//             pi_b,
//             pi_c,
//             protocol: "groth16".to_string(),
//             // _phantom: PhantomData,
//         }
//     }
// }
//
// impl<P: BnConfig> Into<Proof<Bn<P>>> for RapidSnarkProof<P> {
//     fn into(&self) -> Proof<Bn<P>> {
//         let x_coord = |v: &str| {
//             let v = BigUint::from_str_radix(v, 10).unwrap();
//             ark_ff::BigInteger256::from(v)
//         };
//         let a = bn::G1Projective::<P>::new(self.pi_a[0].parse::<ark_ff::BigInteger256>().unwrap(), self.pi_a[1].parse::<ark_ff::BigInteger256>().unwrap(), ark_ff::BigInteger256::from(1)).into_affine();
//         let b = bn::G2Projective::<P>::new().into_affine();
//
//
//         P::Fp2Config::Fp::zero();
//         // <P::G2Config as CurveConfig>::BaseField::new();
//         // ;
//         // Fp2<<P as BnConfig>::Fp2Config>>::BaseField::new();
//         // Bn<P>::G2Projective::new().into_affine();
//
//
//         let c = bn::G1Projective::<P>::new(self.pi_c[0].parse::<ark_ff::BigInteger256>().unwrap(), self.pi_c[1].parse::<ark_ff::BigInteger256>().unwrap(), ark_ff::BigInteger256::from(1)).into_affine();
//         Proof { a, b, c }
//     }
// }

#[cfg(test)]
mod test {
    use crate::proof::BnConfig;
    use ark_bn254::Bn254;
    use ark_groth16::Proof;
    use ark_serialize::CanonicalDeserialize;
    use crate::proof::RapidSnarkProof;
    // use crate::proof::RapidSnarkProof1;
    use ark_bn254::{Config};
    use ark_ec::bn::Bn;
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

        let deserialized: RapidSnarkProof<Config> = serde_json::from_str(json_str).expect("Failed to deserialize");

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