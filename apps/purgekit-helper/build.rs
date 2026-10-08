use embed_manifest::manifest::ExecutionLevel;
use embed_manifest::{embed_manifest, new_manifest};

#[path = "../winres.rs"]
mod winres;

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(
            new_manifest("PurgeKit.Helper")
                .requested_execution_level(ExecutionLevel::RequireAdministrator),
        )
        .expect("unable to embed manifest");
        // Same icon as the app; the UAC prompt shows the icon and description.
        winres::embed(&winres::Exe {
            description: "PurgeKit cleanup helper",
            internal_name: "purgekit-helper",
            original_filename: "purgekit-helper.exe",
        });
    }
    println!("cargo:rerun-if-changed=build.rs");
}
