#![feature(rustc_private)]
#![feature(box_patterns)]

extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;

use log::info;

use rust_mir_checker::analysis::option;
use rust_mir_checker::{analysis, utils};
use rustc_session::config::ErrorOutputType;
use std::env;
use std::process;

fn main() -> process::ExitCode {
    pretty_env_logger::init();

    let mut rustc_args = env::args_os()
        .enumerate()
        .map(|(i, arg)| {
            arg.into_string().unwrap_or_else(|arg| {
                let dcx = rustc_session::EarlyDiagCtxt::new(ErrorOutputType::default());
                dcx.early_fatal(format!("Argument {} is not valid Unicode: {:?}", i, arg))
            })
        })
        .collect::<Vec<_>>();

    if let Some(sysroot) = utils::compile_time_sysroot() {
        let sysroot_flag = "--sysroot";
        if !rustc_args.iter().any(|e| e == sysroot_flag) {
            rustc_args.push(sysroot_flag.to_owned());
            rustc_args.push(sysroot);
        }
    }

    if env::var_os("MIR_CHECKER_BE_RUSTC").is_some() {
        let mut callbacks = rustc_driver::TimePassesCallbacks::default();
        rustc_driver::catch_with_exit_code(move || {
            rustc_driver::run_compiler(&rustc_args, &mut callbacks)
        })
    } else {
        let always_encode_mir = "-Zalways_encode_mir";
        if !rustc_args.iter().any(|e| e == always_encode_mir) {
            rustc_args.push(always_encode_mir.to_owned());
        }

        rustc_args.push("-Cpanic=abort".to_owned());

        let analysis_options = option::AnalysisOption::from_args(&mut rustc_args);
        info!("Analysis Option: {:?}", analysis_options);

        let mut callbacks = analysis::callback::MirCheckerCallbacks::new(analysis_options);

        rustc_driver::catch_with_exit_code(move || {
            rustc_driver::run_compiler(&rustc_args, &mut callbacks)
        })
    }
}
