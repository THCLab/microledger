use crate::{
    ControlingIdentifier, DigitalFingerprint, Seal, SealProvider, Serialization, Signature,
};

pub struct Block<I, D, C, P>
where
    I: Seal,
    D: DigitalFingerprint,
    C: ControlingIdentifier,
    P: SealProvider,
{
    seals: I,
    previos: Option<D>,
    rules: C,
    seal_provider: P,
}

impl<I, D, C, P> Serialization for Block<I, D, C, P>
where
    I: Seal,
    D: DigitalFingerprint,
    C: ControlingIdentifier,
    P: SealProvider,
{
    fn serialize(&self) -> Vec<u8> {
        todo!()
    }
}

pub struct SignedBlock<I, C, D, S, P>
where
    I: Seal,
    C: ControlingIdentifier,
    D: DigitalFingerprint,
    S: Signature,
    P: SealProvider,
{
    block: Block<I, D, C, P>,
    signatures: Vec<S>,
}

impl<I, D, C, P> Block<I, D, C, P>
where
    I: Seal,
    C: ControlingIdentifier,
    D: DigitalFingerprint,
    P: SealProvider,
{
    fn check_block(&self, block: Block<I, D, C, P>) -> bool {
        match &block.previos {
            Some(prev) => {
                // check if previous event matches
                if prev.verify_binding(&self.serialize()) {
                    // check if seal of given hash exists
                    if block.seal_provider.check(&self.seals) {
                        // ok, block can be added
                        true
                    } else {
                        // anchored data doesn't exist in seal provider
                        false
                    }
                } else {
                    // previous block doesn't match
                    false
                }
            }
            None => {
                // it's initial block
                todo!()
            }
        }
    }

    pub fn append<S: Signature>(&self, block: SignedBlock<I, C, D, S, P>) -> bool {
        if self.rules.check_signatures(block.signatures) {
            self.check_block(block.block)
        } else {
            // signatures doesn't match the rules
            false
        };
        todo!()
    }
}
