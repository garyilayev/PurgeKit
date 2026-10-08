use embed_manifest::manifest::{DpiAwareness, ExecutionLevel, Setting};
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    // Runs as the invoking user. Only purgekit-helper.exe ever elevates.
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(
            new_manifest("PurgeKit")
                .requested_execution_level(ExecutionLevel::AsInvoker)
                .long_path_aware(Setting::Enabled)
                .dpi_awareness(DpiAwareness::PerMonitorV2),
        )
        .expect("unable to embed manifest");
        embed_resource::compile("../../ui/purgekit.rc", embed_resource::NONE)
            .manifest_required()
            .expect("unable to embed the app icon");
    }
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("../../ui/app.slint", config).expect("compile ui/app.slint");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../ui/purgekit.ico");
}
