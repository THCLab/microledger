use crate::Result;
pub trait Verifier {
    type Signature;

    fn verify(&self, data: &[u8], s: Vec<Self::Signature>) -> Result<bool>;
}
