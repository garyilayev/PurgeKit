use embed_manifest::manifest::{DpiAwareness, ExecutionLevel, Setting};
use embed_manifest::{embed_manifest, new_manifest};

#[path = "../winres.rs"]
mod winres;

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
        winres::embed(&winres::Exe {
            description: "PurgeKit",
            internal_name: "purgekit",
            original_filename: "purgekit.exe",
        });
    }
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("../../ui/app.slint", config).expect("compile ui/app.slint");
    println!("cargo:rerun-if-changed=build.rs");
}
