import { compact } from "./format";
import type { Status } from "./api";

// One source of truth for the pipeline stages — drives the deck cards, the
// click-through modal, and the /pipeline/[slug] detail pages so every metric is
// defined once.
export type StageSlug = "collect" | "ingest" | "detect" | "correlate" | "attribute" | "respond";

export type StageState = { label: string; tone?: "ok" | "warn" | "err" };

export type StageDef = {
  slug: StageSlug;
  name: string;          // card title
  word: string;          // the pipeline-arrow word
  cls: string;           // accent color class (st-*)
  blurb: string;         // one line under the title
  about: string;         // what this stage does (modal + detail)
  activityStage?: string; // which activity.stage entries belong here
  state: (s: Status | null) => StageState;
  lines: (s: Status | null) => [string, string][];
  error?: (s: Status | null) => string | null;
};

const num = (n: number | undefined) => String(n ?? 0);

export const STAGES: StageDef[] = [
  {
    slug: "collect",
    name: "Collect",
    word: "collect",
    cls: "st-coll",
    blurb: "agents → telemetry",
    about:
      "Lightweight agents on each host tail authentication, process and network telemetry and stream it to Prahari. Agents initiate every connection outbound, so no inbound ports are opened on the monitored machines.",
    state: (s) => {
      const n = s?.fleet?.hosts?.length ?? 0;
      return n > 0 ? { label: "ACTIVE", tone: "ok" } : { label: "IDLE" };
    },
    lines: (s) => {
      const agents = s?.fleet?.hosts ?? [];
      const tailing = agents.reduce(
        (n, h) => n + Object.values(h.agent ?? {}).filter((x) => x.state === "tailing").length, 0);
      const errs = agents.reduce(
        (n, h) => n + Object.values(h.agent ?? {}).filter((x) => x.state === "error").length, 0);
      return [
        ["agents", num(agents.length)],
        ["sources tailing", errs > 0 ? `${tailing} · ${errs} error` : num(tailing)],
        ["events / min", num(s?.fleet?.rate_epm)],
      ];
    },
  },
  {
    slug: "ingest",
    name: "Ingest · screen",
    word: "screen",
    cls: "st-base",
    activityStage: "baseline",
    blurb: "batch → learn normal",
    about:
      "Incoming events are batched and, during a one-time warmup, used to learn this fleet's normal. Suspicious events are screened out of the baseline so an attacker can't poison it. The frozen baseline is persisted and survives restarts — re-learning is a deliberate operator action.",
    state: (s) => (s?.mode === "warmup" ? { label: "LEARNING", tone: "warn" } : { label: "FROZEN", tone: "ok" }),
    lines: (s) => {
      const st = s?.pipeline?.stats ?? {};
      return [
        ["batches", compact(st.batches ?? 0)],
        ["events", compact(st.events ?? 0)],
        ["screened out", num(st.screened)],
      ];
    },
  },
  {
    slug: "detect",
    name: "Detect · sentinels",
    word: "detect",
    cls: "st-sent",
    activityStage: "sentinel",
    blurb: "score vs baseline",
    about:
      "Two unsupervised sentinels (auth + network) score every event against the learned baseline; behavioural heuristics catch recon commands and activity corroborated by other sensors on the same host. Commands seen during warmup are known-normal and never flagged.",
    state: (s) => {
      const d = s?.pipeline?.detectors;
      const n = (d?.auth ? 1 : 0) + (d?.network ? 1 : 0);
      return { label: `${n}/2 models`, tone: n > 0 ? "ok" : undefined };
    },
    lines: (s) => {
      const st = s?.pipeline?.stats ?? {};
      const anom = (st.auth_anomaly ?? 0) + (st.net_anomaly ?? 0);
      const corr = (st.process_corroborated ?? 0) + (st.external_corroborated ?? 0);
      return [
        ["ML anomalies", `${anom} (auth ${st.auth_anomaly ?? 0} · net ${st.net_anomaly ?? 0})`],
        ["heuristics", `${(st.discovery ?? 0) + corr} (disc ${st.discovery ?? 0} · corr ${corr})`],
        ["known-normal cmds", num(s?.pipeline?.process_baseline_size)],
      ];
    },
  },
  {
    slug: "correlate",
    name: "Correlate",
    word: "correlate",
    cls: "st-corr",
    activityStage: "correlator",
    blurb: "fuse into incidents",
    about:
      "Flagged events on the same host are fused within a sliding window. An incident becomes high-confidence only when it spans two or more sensors and two or more kill-chain phases — the compound signal a single alert can never give.",
    state: (s) => ({ label: `${s?.pipeline?.window_seconds ?? "—"}s window` }),
    lines: (s) => [
      ["flagged in window", num(s?.flagged_recent)],
      ["open incidents", num(s?.incident_count)],
      ["high-confidence", num(s?.high_confidence_count)],
    ],
  },
  {
    slug: "attribute",
    name: "Attribute · LLM",
    word: "attribute",
    cls: "st-attr",
    activityStage: "attribution",
    blurb: "map to ATT&CK",
    about:
      "For each high-confidence incident a local LLM maps the fused timeline to MITRE ATT&CK — cited techniques, a grounded explanation and a predicted next tactic. Retrieval runs over the technique corpus and the model is local, so attribution is fully air-gapped.",
    state: (s) => (s?.pipeline?.attribution_error ? { label: "ERROR", tone: "err" } : { label: "READY", tone: "ok" }),
    error: (s) => s?.pipeline?.attribution_error ?? null,
    lines: (s) => {
      const st = s?.pipeline?.stats ?? {};
      const m = s?.pipeline?.models;
      return [
        ["chat / embed", m ? `${m.chat} · ${m.embed}` : "—"],
        ["ATT&CK mapped", num(st.attributed)],
        ["failed", num(st.attribution_failed)],
      ];
    },
  },
  {
    slug: "respond",
    name: "Respond · gate",
    word: "respond",
    cls: "st-resp",
    activityStage: "responder",
    blurb: "recommend + human gate",
    about:
      "The planner recommends containment playbooks for each incident, most-contained first. Nothing runs until an operator approves at the human gate; destructive actions additionally require arming and an explicit agent opt-in. Reversible actions can be reverted.",
    state: (s) => {
      const p = s?.response?.pending ?? 0;
      return p > 0 ? { label: `${p} PENDING`, tone: "warn" } : { label: "READY", tone: "ok" };
    },
    lines: (s) => {
      const r = s?.response;
      return [
        ["recommended", num(r?.total)],
        ["awaiting approval", num(r?.pending)],
        ["executed / reverted", `${r?.executed ?? 0} / ${r?.reverted ?? 0}`],
      ];
    },
  },
];

export const STAGE_BY_SLUG: Record<string, StageDef> =
  Object.fromEntries(STAGES.map((s) => [s.slug, s]));
