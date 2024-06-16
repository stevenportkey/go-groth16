use serde::{Deserialize, Serialize};
use ark_ec::CurveGroup;
use ark_groth16::Proof;
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
            D: serde::Deserializer<'de>
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
    use ark_bn254::Bn254;
    use ark_groth16::Proof;
    use ark_serialize::CanonicalDeserialize;
    use crate::proof::RapidSnarkProof;
    use ark_serialize::CanonicalSerialize;

    #[test]
    fn test_conversion() {
        let proof_hex = "6b74506effb0f09b3edfff7952ed3971a5fdac3cfc4dd5745e008d4f4883d4af0eaac5c5f4bd927d22763342bd5422f04d3bca54e0f54d3aea7f3f5674d6a61a53fb542dbb912dbb2ebcb55c9e6742dc3e0a658b034e10430b74383b235fe18f5ea0d3e43353313134bfb1d80898de16a6d0bc8c686ae922ccf61b67af9bf922";
        let proof = hex::decode(proof_hex).unwrap();
        let proof = Proof::<Bn254>::deserialize_compressed(&*proof).unwrap();
        let proof = RapidSnarkProof::from(proof);
        let proof: Proof<Bn254> = proof.into();
        let mut v = Vec::new();
        let _ = proof.serialize_compressed(&mut v).unwrap();
        assert_eq!(proof_hex, hex::encode(v));
    }
}