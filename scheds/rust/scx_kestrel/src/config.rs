// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::fs;
use std::io::Read;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::LayerGrowthAlgo;
use crate::bpf_intf;

use scx_utils::Cpumask;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LayerConfig {
    pub specs: Vec<LayerSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerSpec {
    pub name: String,
    #[serde(skip)]
    pub cpuset: Option<Cpumask>,
    pub comment: Option<String>,
    pub template: Option<LayerMatch>,
    pub matches: Vec<Vec<LayerMatch>>,
    pub kind: LayerKind,
}

impl LayerSpec {
    pub fn parse(input: &str) -> Result<Vec<Self>> {
        let config: LayerConfig = if input.starts_with("f:") || input.starts_with("file:") {
            let mut f = fs::OpenOptions::new()
                .read(true)
                .open(input.split_once(':').unwrap().1)?;
            let mut content = String::new();
            f.read_to_string(&mut content)?;
            serde_json::from_str(&content)?
        } else {
            serde_json::from_str(input)?
        };
        Ok(config.specs)
    }

    pub fn nodes(&self) -> &Vec<usize> {
        &self.kind.common().nodes
    }

    pub fn llcs(&self) -> &Vec<usize> {
        &self.kind.common().llcs
    }

    pub fn nodes_mut(&mut self) -> &mut Vec<usize> {
        &mut self.kind.common_mut().nodes
    }

    pub fn llcs_mut(&mut self) -> &mut Vec<usize> {
        &mut self.kind.common_mut().llcs
    }
}

/// Highest hint scx_kestrel matches. The kernel enforces the same bound in
/// sched_setattr; a value above it is a config error, not a no-match.
pub const KESTREL_HINT_MAX: u32 = 1024;

pub fn kestrel_hint_in_range(hint: u32) -> bool {
    hint <= KESTREL_HINT_MAX
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum LayerPlacement {
    #[default]
    Standard,
    Sticky,
    Floating,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerMatch {
    CgroupPrefix(String),
    CgroupSuffix(String),
    CgroupContains(String),
    CgroupRegex(String),
    CommPrefix(String),
    CommPrefixExclude(String),
    PcommPrefix(String),
    PcommPrefixExclude(String),
    NiceAbove(i32),
    NiceBelow(i32),
    NiceEquals(i32),
    UIDEquals(u32),
    GIDEquals(u32),
    PIDEquals(u32),
    PPIDEquals(u32),
    TGIDEquals(u32),
    NSPIDEquals(u64, u32),
    NSEquals(u32),
    CmdJoin(String),
    IsGroupLeader(bool),
    IsKthread(bool),
    UsedGpuTid(bool),
    UsedGpuPid(bool),
    AvgRuntime(u64, u64),
    HintEquals(u64),
    KestrelHint(u32),
    SystemCpuUtilBelow(f64),
    DsqInsertBelow(f64),
    NumaNode(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerCommon {
    #[serde(default)]
    pub min_exec_us: u64,
    #[serde(default)]
    pub yield_ignore: f64,
    #[serde(default)]
    pub slice_us: u64,
    #[serde(default)]
    pub fifo: bool,
    #[serde(default)]
    pub preempt: bool,
    #[serde(default)]
    pub preempt_first: bool,
    #[serde(default)]
    pub exclusive: bool,
    #[serde(default, skip_serializing)]
    pub allow_node_aligned: Option<bool>,
    #[serde(default)]
    pub skip_remote_node: bool,
    #[serde(default)]
    pub prev_over_idle_core: bool,
    #[serde(default)]
    pub weight: u32,
    #[serde(default)]
    pub disallow_open_after_us: Option<u64>,
    #[serde(default)]
    pub disallow_preempt_after_us: Option<u64>,
    #[serde(default)]
    pub xllc_mig_min_us: f64,
    #[serde(default, skip_serializing)]
    pub idle_smt: Option<bool>,
    #[serde(default)]
    pub growth_algo: LayerGrowthAlgo,
    /// Half-life in milliseconds for holding recent utilization peaks when
    /// deciding whether a layer should shrink. 0 disables peak holding.
    #[serde(default)]
    pub util_peak_half_life_ms: u64,
    #[serde(default)]
    pub perf: u64,
    #[serde(default)]
    pub idle_resume_us: Option<u32>,
    #[serde(default)]
    pub nodes: Vec<usize>,
    #[serde(default)]
    pub llcs: Vec<usize>,
    #[serde(default)]
    pub placement: LayerPlacement,
    #[serde(default)]
    pub member_expire_ms: u64,
    #[serde(default = "default_xnuma_threshold")]
    pub xnuma_threshold: (f64, f64),
    #[serde(default = "default_xnuma_threshold_delta")]
    pub xnuma_threshold_delta: (f64, f64),
}

fn default_xnuma_threshold() -> (f64, f64) {
    (0.6, 0.7)
}

fn default_xnuma_threshold_delta() -> (f64, f64) {
    (0.2, 0.3)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerKind {
    Confined {
        util_range: (f64, f64),
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,

        #[serde(default)]
        cpus_range_frac: Option<(f64, f64)>,

        #[serde(default)]
        membw_gb: Option<f64>,

        #[serde(default)]
        protected: bool,

        #[serde(flatten)]
        common: LayerCommon,
    },
    Grouped {
        util_range: (f64, f64),
        #[serde(default)]
        util_includes_open_cputime: bool,
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,

        #[serde(default)]
        cpus_range_frac: Option<(f64, f64)>,

        #[serde(default)]
        membw_gb: Option<f64>,

        #[serde(default)]
        protected: bool,

        /// When true, idle CPU selection only considers the layer's own
        /// CPUs until the layer becomes saturated (i.e., no idle CPU is
        /// found and check_no_idle is set) or the system is fully
        /// allocated (all CPUs assigned to layers). At that point, idle
        /// search falls back to unprotected CPUs like a normal Grouped
        /// layer. Provides Confined-style cache locality under normal
        /// load with Grouped-style overflow under pressure.
        #[serde(default)]
        idle_confined: bool,

        #[serde(flatten)]
        common: LayerCommon,
    },
    Open {
        #[serde(flatten)]
        common: LayerCommon,
    },
}

impl LayerKind {
    pub fn as_bpf_enum(&self) -> i32 {
        match self {
            LayerKind::Confined { .. } => bpf_intf::layer_kind_LAYER_KIND_CONFINED as i32,
            LayerKind::Grouped { .. } => bpf_intf::layer_kind_LAYER_KIND_GROUPED as i32,
            LayerKind::Open { .. } => bpf_intf::layer_kind_LAYER_KIND_OPEN as i32,
        }
    }

    pub fn common(&self) -> &LayerCommon {
        match self {
            LayerKind::Confined { common, .. }
            | LayerKind::Grouped { common, .. }
            | LayerKind::Open { common, .. } => common,
        }
    }

    pub fn common_mut(&mut self) -> &mut LayerCommon {
        match self {
            LayerKind::Confined { common, .. }
            | LayerKind::Grouped { common, .. }
            | LayerKind::Open { common, .. } => common,
        }
    }

    pub fn util_range(&self) -> Option<(f64, f64)> {
        match self {
            LayerKind::Confined { util_range, .. } | LayerKind::Grouped { util_range, .. } => {
                Some(*util_range)
            }
            _ => None,
        }
    }

    pub fn util_includes_open_cputime(&self) -> bool {
        match self {
            LayerKind::Grouped {
                util_includes_open_cputime,
                ..
            } => *util_includes_open_cputime,
            _ => false,
        }
    }
}

#[cfg(test)]
mod kestrel_tests {
    use super::*;

    #[test]
    fn kestrel_hint_match_parses_and_serializes() {
        let input = r#"[{
            "name": "kestrel-browser-active",
            "matches": [[{ "KestrelHint": 3 }]],
            "kind": { "Grouped": { "util_range": [0.2, 0.8], "weight": 500 } }
        }]"#;
        let specs = LayerSpec::parse(input).expect("KestrelHint parses");
        assert_eq!(specs.len(), 1);
        match &specs[0].matches[0][0] {
            LayerMatch::KestrelHint(hint) => assert_eq!(*hint, 3),
            other => panic!("expected KestrelHint, got {other:?}"),
        }
        let json = serde_json::to_string(&specs[0]).expect("serializes");
        assert!(json.contains("KestrelHint"));
    }

    #[test]
    fn baked_layers_cover_every_documented_class() {
        let config: LayerConfig =
            serde_json::from_str(include_str!("../kestrel-layers.json")).expect("baked JSON parses");
        let mut hints = Vec::new();
        for spec in &config.specs {
            for block in &spec.matches {
                for m in block {
                    if let LayerMatch::KestrelHint(h) = m {
                        hints.push((*h, spec.name.as_str()));
                    }
                }
            }
        }
        assert_eq!(
            hints,
            vec![
                (1, "kestrel-desktop"),
                (2, "kestrel-term"),
                (3, "kestrel-browser-active"),
                (4, "kestrel-browser-background"),
                (5, "kestrel-game"),
            ]
        );
        assert_eq!(config.specs.last().unwrap().name, "default");
        assert!(config.specs.last().unwrap().matches.iter().all(|block| block.is_empty()));
    }

    #[test]
    fn hint_range_is_inclusive() {
        assert!(kestrel_hint_in_range(0));
        assert!(kestrel_hint_in_range(1024));
        assert!(!kestrel_hint_in_range(1025));
    }
}
