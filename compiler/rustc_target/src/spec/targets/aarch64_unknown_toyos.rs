use crate::spec::{Arch, Cc, LinkerFlavor, Lld, StackProbeType, Target, TargetMetadata, base};

pub(crate) fn target() -> Target {
    let mut opts = base::toyos::opts();
    opts.linker = Some("rust-lld".into());
    opts.linker_flavor = LinkerFlavor::Gnu(Cc::No, Lld::Yes);
    opts.features = "+v8a".into();
    opts.max_atomic_width = Some(128);
    opts.stack_probes = StackProbeType::Inline;

    Target {
        llvm_target: "aarch64-unknown-none-elf".into(),
        metadata: TargetMetadata {
            description: Some("ARM64 ToyOS".into()),
            tier: Some(3),
            host_tools: Some(false),
            std: Some(true),
        },
        pointer_width: 64,
        data_layout: "e-m:e-p270:32:32-p271:32:32-p272:64:64-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32".into(),
        arch: Arch::AArch64,
        options: opts,
    }
}
