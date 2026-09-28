/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::process::ExitCode;
use std::sync::Arc;

use clap::{ArgMatches, Command};

use super::{BenchTarget, BenchTaskContext, ProcArgs};

mod opts;
use opts::BenchIcapArgs;

mod stats;
use stats::{IcapHistogram, IcapHistogramRecorder, IcapRuntimeStats};

mod task;
use task::IcapTaskContext;

pub const COMMAND: &str = "icap";

struct IcapTarget {
    args: Arc<BenchIcapArgs>,
    stats: Arc<IcapRuntimeStats>,
    histogram: Option<IcapHistogram>,
    histogram_recorder: IcapHistogramRecorder,
}

impl BenchTarget<IcapRuntimeStats, IcapHistogram, IcapTaskContext> for IcapTarget {
    fn new_context(&self) -> anyhow::Result<IcapTaskContext> {
        IcapTaskContext::new(&self.args, &self.stats, self.histogram_recorder.clone())
    }

    fn fetch_runtime_stats(&self) -> Arc<IcapRuntimeStats> {
        self.stats.clone()
    }

    fn take_histogram(&mut self) -> Option<IcapHistogram> {
        self.histogram.take()
    }
}

pub fn command() -> Command {
    opts::add_icap_args(Command::new(COMMAND))
}

pub async fn run(proc_args: &Arc<ProcArgs>, cmd_args: &ArgMatches) -> anyhow::Result<ExitCode> {
    let icap_args = opts::parse_icap_args(cmd_args)?;

    let (histogram, histogram_recorder) = IcapHistogram::new();
    let target = IcapTarget {
        args: Arc::new(icap_args),
        stats: Arc::new(IcapRuntimeStats::default()),
        histogram: Some(histogram),
        histogram_recorder,
    };

    super::run(target, proc_args).await
}
