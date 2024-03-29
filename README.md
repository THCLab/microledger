# License

EUPL 1.2 

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

# Overview

Rust based implementation of the Microledger concept proposed [here](https://github.com/the-human-colossus-foundation/microledger-spec/blob/main/microledger.md). 

Microledger is a form of representation of state that assumes existence of chain of blocks, which are cryptographically bound. Microledger does not have an owner or set of owners. In that regard what is relevant is the `controlling identifiers` section of any block in the chain. It informs who is authorized to anchor new block and this is solely possible by those specified in this section of the block. Such an approach also allows to create more complex chains or cross chains that constitute a [DAG](https://en.wikipedia.org/wiki/Directed_acyclic_graph). 

## Usage

See https://github.com/THCLab/microledger/blob/main/tests/test.rs for sample usage.
