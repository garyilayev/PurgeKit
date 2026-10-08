use embed_manifest::manifest::ExecutionLevel;
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(
            new_manifest("PurgeKit.Helper")
                .requested_execution_level(ExecutionLevel::RequireAdministrator),
        )
        .expect("unable to embed manifest");
        // Same icon as the app, so the UAC prompt shows PurgeKit's icon.
        embed_resource::compile("../../ui/purgekit.rc", embed_resource::NONE)
            .manifest_required()
            .expect("unable to embed the app icon");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../ui/purgekit.ico");
}
