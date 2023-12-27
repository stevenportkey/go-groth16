use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct ProvingOutput {
    pub(crate) public_inputs: Vec<String>,
    pub(crate) proof: String,
}
