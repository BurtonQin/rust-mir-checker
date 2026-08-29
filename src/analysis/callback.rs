use crate::analysis::analyzer::analysis_trait::StaticAnalysis;
use crate::analysis::analyzer::numerical_analysis::NumericalAnalysis;
use crate::analysis::global_context::GlobalContext;
use crate::analysis::option::AnalysisOption;
use log::{error, info};
use rustc_driver::Compilation;
use rustc_interface::interface;
use rustc_middle::ty::TyCtxt;

pub struct MirCheckerCallbacks {
    pub analysis_options: AnalysisOption,
    pub source_name: String,
}

impl MirCheckerCallbacks {
    pub fn new(options: AnalysisOption) -> Self {
        Self {
            analysis_options: options,
            source_name: String::new(),
        }
    }
}

impl rustc_driver::Callbacks for MirCheckerCallbacks {
    /// Called before creating the compiler instance
    fn config(&mut self, config: &mut interface::Config) {
        self.source_name = match &config.input {
            rustc_session::config::Input::File(p) => p.display().to_string(),
            rustc_session::config::Input::Str { name, .. } => format!("{name:?}"),
        };
        config.crate_cfg.push("mir_checker".to_string());
        info!("Source file: {}", self.source_name);
    }

    /// Called after analysis. Return value instructs the compiler whether to
    /// continue the compilation afterwards (defaults to `Compilation::Continue`)
    fn after_analysis<'tcx>(
        &mut self,
        compiler: &interface::Compiler,
        tcx: TyCtxt<'tcx>,
    ) -> Compilation {
        // Skip analysis for core/std/alloc crates
        if self.source_name.ends_with("libcore")
            || self.source_name.ends_with("libstd")
            || self.source_name.ends_with("liballoc")
            || self.source_name.ends_with("libproc_macro")
            || self.source_name.ends_with("build_script_build")
        {
            info!(
                "Find filename that should skip the analysis: {}",
                self.source_name
            );
            return Compilation::Continue;
        }

        // Initialize global analysis context
        if let Some(mut global_context) =
            GlobalContext::new(&compiler.sess, tcx, self.analysis_options.clone())
        {
            // Initialize numerical analyzer
            let mut numerical_analysis = NumericalAnalysis::new(&mut global_context);
            // Run analyzer
            if let Ok(analysis_result) = numerical_analysis.run() {
                info!(
                    "Numerical Analysis Completed: {} ms",
                    analysis_result.analysis_time.as_millis()
                );
            } else {
                error!("Numerical Analysis Failed");
            }
        } else {
            error!("GlobalContext Initialization Failed");
        }
        Compilation::Continue
    }
}
