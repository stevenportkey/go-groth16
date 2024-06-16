use serde::{Deserialize, Serialize};
use crate::proof::RapidSnarkProof;

#[derive(Serialize, Deserialize)]
pub(crate) struct ProvingOutput {
    pub(crate) public_inputs: Vec<String>,
    pub(crate) proof: RapidSnarkProof,
}
