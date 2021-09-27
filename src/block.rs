use crate::{ControlingIdentifiers, DigitalFingerprint, Seals, Serialization, Signatures};

pub struct Block<I, D, C>
where
    I: Seals,
    D: DigitalFingerprint,
    C: ControlingIdentifiers,
{
    seals: I,
    previos: Option<D>,
    rules: C,
}

impl<I, D, C> Serialization for Block<I, D, C>
where
    I: Seals,
    D: DigitalFingerprint,
    C: ControlingIdentifiers,
{
    fn serialize(&self) -> Vec<u8> {
        todo!()
    }
}

pub struct SignedBlock<I, C, D, S>
where
    I: Seals,
    C: ControlingIdentifiers,
    D: DigitalFingerprint,
    S: Signatures,
{
    block: Block<I, D, C>,
    signatures: Vec<S>,
}

impl<I, D, C> Block<I, D, C>
where
    I: Seals,
    C: ControlingIdentifiers,
    D: DigitalFingerprint,
{
    fn check_block(&self, block: Block<I, D, C>) -> bool {
        match &block.previos {
            Some(prev) => {
                // check if previous event matches
                if prev.verify_binding(&self.serialize()) {
                    // check if seal of given hash exists
                    if block.seals.get().is_some() {
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
            },
        }
    }

    pub fn append<S: Signatures>(&self, block: SignedBlock<I, C, D, S>) -> bool {
        if self.rules.check_signatures(block.signatures) {
            self.check_block(block.block)
        } else {
            // signatures doesn't match the rules
            false
        };
        todo!()
    }
}
