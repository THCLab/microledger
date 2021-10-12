use keri::{derivation::self_signing::SelfSigning, prefix::{BasicPrefix, SelfSigningPrefix}};
use microledger::{Serialization, block::Block, microledger::MicroLedger, seal_bundle::{self, SealBundle, SealData}};
use napi::{CallContext, Env, JsBuffer, JsObject, JsString, JsUndefined, Property};
use napi_derive::{js_function, module_exports};
use napi::Result as JsResult;
use said::prefix::SelfAddressingPrefix;

#[module_exports]
pub fn init(mut exports: JsObject, env: Env) -> JsResult<()> {
    let microledger_class = env.define_class(
        "Microledger",
        new,
        &[
            Property::new(&env, "preAnchorBlock")?.with_method(pre_anchor_block),
            Property::new(&env, "anchorBlock")?.with_method(anchor_block),
            Property::new(&env, "getBlocks")?.with_method(get_blocks),
        ],
    )?;
    exports.set_named_property("Microledger", microledger_class)?;

    Ok(())
}

type MicroledgerExample = MicroLedger<
    SelfAddressingPrefix,
    BasicPrefix,
    SelfSigningPrefix,
    // SealsAttachement,
>;

#[js_function(0)]
fn new(ctx: CallContext) -> JsResult<JsUndefined> {
    let microledger: MicroledgerExample = MicroLedger::new();
    let mut this: JsObject = ctx.this_unchecked();
    ctx.env.wrap(&mut this, microledger)?;
    ctx.env.get_undefined()
}

#[js_function(2)]
fn pre_anchor_block(ctx: CallContext) -> JsResult<JsString> {
    // Get data that will be attached to block
    let attachements_arg = ctx
        .get::<JsObject>(0)
        .map_err(|_e| napi::Error::from_reason("Missing attachements parameter".into()))?;
    let len = if attachements_arg.is_array()? {
        attachements_arg.get_array_length()?
    } else {
        0
    };
    let mut seal_bundle = SealBundle::new();
    for i in 0..len {
        let data = attachements_arg
            .get_element::<JsString>(i)?
            .into_utf8()
            .map_err(|_e| napi::Error::from_reason("Missing attachement parameter".into()))?
            .as_str()?
            .to_owned();
        seal_bundle = seal_bundle.attach(SealData::AttachedData(data));
    }
    // Get controlling identifiers
    let controlling_ids_arg = ctx.get::<JsObject>(1).map_err(|_e| {
        napi::Error::from_reason("Missing controlling identfiers parameter".into())
    })?;
    let len = if controlling_ids_arg.is_array()? {
        controlling_ids_arg.get_array_length()?
    } else {
        0
    };
    let mut controlling_ids: Vec<BasicPrefix> = vec![];
    for i in 0..len {
        let data = controlling_ids_arg
            .get_element::<JsString>(i)?
            .into_utf8()
            .map_err(|_e| napi::Error::from_reason("Missing prefix parameter".into()))?
            .as_str()?
            .to_owned();
        let id: BasicPrefix = data.parse().unwrap();

        controlling_ids.push(id);
    }
    let this: JsObject = ctx.this_unchecked();
    let microledger: &MicroledgerExample = ctx.env.unwrap(&this)?;

    let block = microledger.pre_anchor_block(controlling_ids, &seal_bundle);
    let block_str = String::from_utf8(Serialization::serialize(&block)).unwrap();

    ctx.env.create_string(&block_str)
}

#[js_function(2)]
fn anchor_block(ctx: CallContext) -> JsResult<JsString> {
    let block = ctx
        .get::<JsString>(0)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing block parameter".into()))?
        .as_str()?
        .to_owned();
    let block: Block<SelfAddressingPrefix, BasicPrefix> =
        serde_json::from_str(&block).unwrap();
    let signature = ctx.get::<JsBuffer>(1)?.into_value()?.to_vec();

    // todo
    let seal_bundle = SealBundle::new();

    let s = SelfSigning::Ed25519Sha512.derive(signature);
    let signed_block = block.to_signed_block(vec![s], &seal_bundle);

    let this: JsObject = ctx.this_unchecked();
    let microledger: &mut MicroledgerExample = ctx.env.unwrap(&this)?;
    *microledger = microledger.anchor(signed_block.clone()).unwrap();
    // ctx.env.wrap(&mut this, microledger)?;
    // ctx.env.get_undefined()
    ctx.env
        .create_string(&serde_json::to_string(&signed_block).unwrap())
}

#[js_function(0)]
fn get_blocks(ctx: CallContext) -> JsResult<JsString> {
    let this: JsObject = ctx.this_unchecked();
    let microledger: &MicroledgerExample = ctx.env.unwrap(&this)?;
    ctx.env
        .create_string(&serde_json::to_string(&microledger).unwrap())
}

#[cfg(test)]
mod tests {}
