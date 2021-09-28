# Overview

Rust based implementation of the Microledger concept proposed [here](https://github.com/the-human-colossus-foundation/microledger-spec/blob/main/microledger.md). 

Microledger is a form of representation of state that assumes existence of chain of blocks, which are cryptographically bound. Microledger does not have an owner or set of owners. In that regard what is relevant is the `controlling identifiers` section of the last block in chain. It describes who is authorized to anchor new block and this 
