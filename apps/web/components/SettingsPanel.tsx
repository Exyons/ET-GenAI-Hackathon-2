"use client";

import { useCallback, useEffect, useState } from "react";

import {
  addToBlocklist, getOperatorEntries, getSettings, getThreatIntel, listModels,
  putSettings, refreshThreatIntel, removeBlocklist, testConnection,
  type Settings, type ThreatIntelStatus,
} from "../lib/api";
import { Help } from "./Help";
import { ThemeToggle } from "./ThemeToggle";
import { TopBar } from "./TopBar";

const PROVIDER_LABEL: Record<string, string> = {
  ollama: "Ollama (local)",
  ollama_cloud: "Ollama Cloud",
  openai: "OpenAI-compatible",
};
const PROVIDER_DEFAULT_URL: Record<string, string> = {
  ollama: "http://localhost:11434",
  ollama_cloud: "https://ollama.com",
  openai: "https://api.openai.com/v1",
};

type TestState = { ok: boolean; reply?: string; error?: string } | null;

export function SettingsPanel() {
  const [s, setS] = useState<Settings | null>(null);
  const [apiKey, setApiKey] = useState(""); // only sent if the operator types one
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [test, setTest] = useState<TestState>(null);
  const [testing, setTesting] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [modelsMsg, setModelsMsg] = useState("");

  const [ti, setTi] = useState<ThreatIntelStatus | null>(null);
  const [ops, setOps] = useState<{ cidr: string; note: string }[]>([]);
  const [newIp, setNewIp] = useState("");
  const [newNote, setNewNote] = useState("");
  const [feedsText, setFeedsText] = useState("");

  const loadTi = useCallback(() => {
    getThreatIntel().then(setTi).catch(() => {});
    getOperatorEntries().then(setOps).catch(() => {});
  }, []);

  useEffect(() => {
    getSettings().then((v) => { setS(v); setFeedsText(v.threatintel_feeds.join("\n")); }).catch(() => {});
    loadTi();
  }, [loadTi]);

  if (!s) {
    return (
      <main className="wrap">
        <TopBar nav />
        <p className="mono dim" style={{ marginTop: 28 }}>Loading settings — is the API running?</p>
      </main>
    );
  }

  const set = (patch: Partial<Settings>) => setS({ ...s, ...patch });
  const onProvider = (provider: string) =>
    set({ provider, base_url: PROVIDER_DEFAULT_URL[provider] ?? s.base_url });

  const feeds = () => feedsText.split("\n").map((l) => l.trim()).filter(Boolean);

  const saveModel = async () => {
    setSaving(true); setSaved(false);
    try {
      const patch: Partial<Settings> = {
        provider: s.provider, base_url: s.base_url,
        chat_model: s.chat_model, embed_model: s.embed_model,
      };
      if (apiKey) patch.api_key = apiKey;
      const next = await putSettings(patch);
      setS(next); setApiKey(""); setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } finally { setSaving(false); }
  };

  const runTest = async () => {
    setTesting(true); setTest(null);
    try { setTest(await testConnection()); }
    catch { setTest({ ok: false, error: "request failed" }); }
    finally { setTesting(false); }
  };

  const loadModels = async () => {
    setModelsMsg("loading…"); setModels([]);
    try {
      const r = await listModels();
      if (r.ok) { setModels(r.models); setModelsMsg(r.models.length ? "" : "no models returned"); }
      else setModelsMsg(r.error || "failed");
    } catch { setModelsMsg("failed"); }
  };

  const saveFeeds = async () => {
    await putSettings({ threatintel_feeds: feeds() });
    loadTi();
  };
  const refreshNow = async () => { setTi(await refreshThreatIntel()); };
  const addOp = async () => {
    if (!newIp.trim()) return;
    try {
      const st = await addToBlocklist(newIp.trim(), newNote.trim());
      setTi(st); setNewIp(""); setNewNote(""); getOperatorEntries().then(setOps).catch(() => {});
    } catch { /* invalid IP — ignore, field stays */ }
  };
  const removeOp = async (cidr: string) => {
    const r = await removeBlocklist(cidr);
    setTi(r); getOperatorEntries().then(setOps).catch(() => {});
  };

  return (
    <main className="wrap">
      <TopBar nav />
      <div className="settings">
        <h1 className="set-title">Settings</h1>

        {/* ---- AI model ---- */}
        <section className="set-card">
          <h2>AI model
            <Help wide text="Which local or remote model writes the situation summary and ATT&CK attribution. Ollama runs fully on-box; Ollama Cloud and OpenAI-compatible endpoints reach out over the network." />
          </h2>
          <div className="set-grid">
            <label className="set-field">
              <span>Provider</span>
              <select value={s.provider} onChange={(e) => onProvider(e.target.value)}>
                {s.providers.map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p] ?? p}</option>)}
              </select>
            </label>
            <label className="set-field">
              <span>Endpoint (base URL)</span>
              <input value={s.base_url} onChange={(e) => set({ base_url: e.target.value })} className="mono" />
            </label>
            <label className="set-field">
              <span>API key {s.provider === "ollama" && <span className="dim">— not needed for local</span>}</span>
              <input type="password" className="mono" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
                placeholder={s.api_key_set ? "•••••••• (saved — leave blank to keep)" : "paste key"} />
            </label>
            <label className="set-field">
              <span>Chat model</span>
              <input list="model-list" className="mono" value={s.chat_model} onChange={(e) => set({ chat_model: e.target.value })} />
            </label>
            <label className="set-field">
              <span>Embed model<Help text="Powers ATT&CK retrieval. Changing it re-embeds the doctrine corpus on the next incident." /></span>
              <input list="model-list" className="mono" value={s.embed_model} onChange={(e) => set({ embed_model: e.target.value })} />
            </label>
            <datalist id="model-list">{models.map((m) => <option key={m} value={m} />)}</datalist>
          </div>
          <div className="set-actions">
            <button type="button" className="btn go" onClick={saveModel} disabled={saving}>
              {saving ? "saving…" : saved ? "saved ✓" : "Save model"}
            </button>
            <button type="button" className="btn" onClick={runTest} disabled={testing}>
              {testing ? "testing…" : "Test connection"}
            </button>
            <button type="button" className="btn" onClick={loadModels}>Load available models</button>
            {modelsMsg && <span className="set-note mono dim">{modelsMsg}</span>}
            {test && (
              <span className={`set-test mono ${test.ok ? "ok" : "err"}`}>
                {test.ok ? `✓ reachable — “${test.reply}”` : `✕ ${test.error}`}
              </span>
            )}
          </div>
        </section>

        {/* ---- Threat intel / blocklist ---- */}
        <section className="set-card">
          <h2>Threat intel &amp; blocklist
            <Help wide text="Blocklist feeds are downloaded on a schedule so reputation data doesn't go stale; you can also maintain your own list. Leave feeds empty to run fully offline on the bundled + operator entries." />
          </h2>
          {ti && (
            <div className="set-tistat mono">
              <span>{ti.blocklist_entries} entries</span>
              <span>· sources: {ti.blocklist_sources.join(", ") || "none"}</span>
              <span>· last refresh: {ti.last_update ? ti.last_update.replace("T", " ").slice(0, 19) + " UTC" : "never"}</span>
            </div>
          )}
          <label className="set-field">
            <span>Feed URLs <span className="dim">— one per line</span></span>
            <textarea className="mono" rows={3} value={feedsText} onChange={(e) => setFeedsText(e.target.value)}
              placeholder="https://…/firehol_level1.netset" />
          </label>
          <div className="set-actions">
            <button type="button" className="btn go" onClick={saveFeeds}>Save feeds</button>
            <button type="button" className="btn" onClick={refreshNow}>Refresh now</button>
          </div>
          {ti && Object.keys(ti.feeds).length > 0 && (
            <div className="set-feeds mono">
              {Object.entries(ti.feeds).map(([url, f]) => (
                <div key={url} className={`set-feed ${f.ok ? "ok" : "err"}`}>
                  <span className="u">{url}</span>
                  <span className="r">{f.ok ? `${f.entries} entries` : f.error}</span>
                </div>
              ))}
            </div>
          )}

          <div className="set-sub">Your blocklist</div>
          <div className="set-oprow">
            <input className="mono" placeholder="IP or CIDR (e.g. 45.9.0.0/16)" value={newIp} onChange={(e) => setNewIp(e.target.value)} />
            <input className="mono" placeholder="note (optional)" value={newNote} onChange={(e) => setNewNote(e.target.value)} />
            <button type="button" className="btn arm" onClick={addOp}>⚑ Add</button>
          </div>
          {ops.length === 0 ? (
            <p className="mono dim set-none">No operator entries yet.</p>
          ) : (
            <div className="set-oplist">
              {ops.map((o) => (
                <div key={o.cidr} className="set-op mono">
                  <span className="c">{o.cidr}</span>
                  <span className="n">{o.note}</span>
                  <button type="button" className="set-rm" onClick={() => removeOp(o.cidr)} aria-label={`remove ${o.cidr}`}>remove</button>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ---- Theme ---- */}
        <section className="set-card">
          <h2>Theme</h2>
          <ThemeToggle />
        </section>
      </div>
    </main>
  );
}
