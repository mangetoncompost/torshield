<script>
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';

  let state = $state({
    active: false,
    tor_running: false,
    proxy_active: false,
    ipv6_off: false,
    firefox_hardened: false,
    tor_ip: null,
    real_ip: null,
  });

  let loading = $state(false);
  let rotating = $state(false);
  let statusMsg = $state('');
  let autostart = $state(false);

  onMount(async () => {
    state = await invoke('get_state');
    autostart = await invoke('autostart_is_enabled').catch(() => false);
    await listen('state_changed', (e) => { state = e.payload; });
  });

  async function toggleAutostart() {
    autostart = await invoke('autostart_set', { enabled: !autostart });
  }

  async function toggle() {
    loading = true;
    statusMsg = state.active ? 'Désactivation...' : 'Connexion à Tor...';
    try {
      state = await invoke(state.active ? 'opsec_disable' : 'opsec_enable');
      statusMsg = '';
    } catch (e) {
      statusMsg = 'Erreur : ' + e;
    }
    loading = false;
  }

  async function rotate() {
    rotating = true;
    statusMsg = 'Nouveau circuit...';
    try {
      await invoke('rotate_identity');
      statusMsg = '';
    } catch(e) {
      statusMsg = 'Erreur rotation';
    }
    rotating = false;
  }

  async function refresh() {
    state = await invoke('refresh_ip');
  }

  let layers = $derived([
    { label: 'Tor',     ok: state.tor_running,      detail: state.tor_running ? 'SOCKS5 :9050' : 'Arrêté' },
    { label: 'Proxy',   ok: state.proxy_active,     detail: state.proxy_active ? 'Système macOS actif' : 'Inactif' },
    { label: 'IPv6',    ok: state.ipv6_off,         detail: state.ipv6_off ? 'Désactivé' : 'Actif (risque leak)' },
    { label: 'Firefox', ok: state.firefox_hardened, detail: state.firefox_hardened ? 'WebRTC off · DNS via Tor' : 'Standard' },
  ]);
</script>

<div class="app">

  <div class="header">
    <div class="logo">
      <div class="shield-icon" class:on={state.active}>
        <svg width="18" height="18" viewBox="0 0 20 20" fill="none">
          <path d="M10 2L3 5v5c0 4.4 2.9 8.5 7 9.9C14.1 18.5 17 14.4 17 10V5l-7-3z"
            fill={state.active ? '#4ade80' : '#52525e'}/>
          {#if state.active}
            <path d="M7 10.5l2 2 4-4" stroke="#fff" stroke-width="1.5"
              stroke-linecap="round" stroke-linejoin="round"/>
          {/if}
        </svg>
      </div>
      <span class="brand">TorShield</span>
    </div>
    <button class="icon-btn" onclick={refresh} title="Rafraîchir">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
      </svg>
    </button>
  </div>

  <div class="ip-card" class:on={state.active}>
    <div class="ip-row">
      <span class="ip-label">IP visible</span>
      <span class="ip-val" class:green={state.active && state.tor_ip}>
        {state.active && state.tor_ip ? state.tor_ip : '—'}
      </span>
    </div>
    <div class="ip-sep"></div>
    <div class="ip-row">
      <span class="ip-label">IP réelle</span>
      <span class="ip-val real">{state.real_ip ?? '—'}</span>
    </div>
  </div>

  <div class="toggle-area">
    <button class="toggle" class:on={state.active} class:busy={loading} onclick={toggle} disabled={loading}>
      {#if loading}
        <span class="spin"></span>{statusMsg}
      {:else if state.active}
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/>
          <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        Désactiver
      {:else}
        <svg width="14" height="14" viewBox="0 0 20 20" fill="none">
          <path d="M10 2L3 5v5c0 4.4 2.9 8.5 7 9.9C14.1 18.5 17 14.4 17 10V5l-7-3z" fill="currentColor"/>
        </svg>
        Activer OPSEC
      {/if}
    </button>
  </div>

  <div class="layers-card">
    <div class="layers-title">Couches</div>
    {#each layers as l}
      <div class="layer">
        <span class="dot" class:ok={l.ok}></span>
        <span class="lname">{l.label}</span>
        <span class="ldetail">{l.detail}</span>
      </div>
    {/each}
  </div>

  {#if state.active}
    <div class="actions-row">
      <button class="act-btn" onclick={rotate} disabled={rotating}>
        {#if rotating}
          <span class="spin sm"></span>Rotation...
        {:else}
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <polyline points="23 4 23 10 17 10"/>
            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
          </svg>
          Nouvelle identité
        {/if}
      </button>
    </div>
  {/if}

  <div class="footer">
    <div class="footer-status">
      <span class="fdot" class:on={state.active}></span>
      <span class="ftext">
        {state.active ? 'Trafic routé via Tor' : 'Non protégé — réseau direct'}
      </span>
    </div>
    <button class="autostart-toggle" onclick={toggleAutostart} title="Lancer au démarrage">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M5 3l14 9-14 9V3z"/>
      </svg>
      <span class:on={autostart}>Démarrage auto</span>
      <span class="toggle-pill" class:on={autostart}></span>
    </button>
  </div>

</div>

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 520px;
    background: var(--bg);
  }

  /* Header */
  .header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 14px 12px;
    border-bottom: 1px solid var(--border);
  }
  .logo { display: flex; align-items: center; gap: 8px; }
  .shield-icon {
    width: 26px; height: 26px; border-radius: 7px;
    background: var(--bg3);
    display: flex; align-items: center; justify-content: center;
    transition: background 0.25s;
  }
  .shield-icon.on { background: color-mix(in srgb, #4ade80 12%, var(--bg3)); }
  .brand { font-size: 14px; font-weight: 600; letter-spacing: -0.3px; }
  .icon-btn {
    background: none; border: none; cursor: pointer;
    color: var(--text-dim); padding: 5px; border-radius: 5px;
    display: flex; transition: color 0.15s;
  }
  .icon-btn:hover { color: var(--text); }

  /* IP card */
  .ip-card {
    margin: 12px 14px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    transition: border-color 0.25s;
  }
  .ip-card.on { border-color: color-mix(in srgb, #4ade80 25%, var(--border)); }
  .ip-row {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 13px;
  }
  .ip-sep { height: 1px; background: var(--border); margin: 0 13px; }
  .ip-label { font-size: 12px; color: var(--text-dim); }
  .ip-val { font-size: 13px; font-weight: 500; font-variant-numeric: tabular-nums; color: var(--text-dim2); }
  .ip-val.green { color: var(--green); }
  .ip-val.real { filter: blur(4px); transition: filter 0.2s; cursor: pointer; }
  .ip-val.real:hover { filter: none; }

  /* Toggle */
  .toggle-area { padding: 0 14px; }
  .toggle {
    width: 100%; padding: 10px 14px;
    border-radius: var(--radius); border: 1px solid var(--border);
    background: var(--bg3); color: var(--text);
    font-size: 13px; font-weight: 500; cursor: pointer;
    display: flex; align-items: center; justify-content: center; gap: 7px;
    transition: all 0.15s;
  }
  .toggle:hover:not(:disabled) { background: var(--bg2); border-color: #3a3a44; }
  .toggle.on {
    background: color-mix(in srgb, #4ade80 8%, var(--bg3));
    border-color: color-mix(in srgb, #4ade80 35%, var(--border));
    color: var(--green);
  }
  .toggle.on:hover:not(:disabled) {
    background: color-mix(in srgb, #f87171 8%, var(--bg3));
    border-color: color-mix(in srgb, #f87171 35%, var(--border));
    color: var(--red);
  }
  .toggle:disabled { opacity: 0.55; cursor: default; }

  /* Layers */
  .layers-card {
    margin: 12px 14px 0;
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
  }
  .layers-title {
    padding: 8px 13px 7px;
    font-size: 10px; font-weight: 600; color: var(--text-dim);
    text-transform: uppercase; letter-spacing: 0.7px;
    border-bottom: 1px solid var(--border);
  }
  .layer {
    display: flex; align-items: center; gap: 9px;
    padding: 8px 13px;
    border-bottom: 1px solid var(--border);
  }
  .layer:last-child { border-bottom: none; }
  .dot {
    width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0;
    background: var(--text-dim); transition: all 0.2s;
  }
  .dot.ok { background: var(--green); box-shadow: 0 0 4px color-mix(in srgb, #4ade80 60%, transparent); }
  .lname { font-size: 12px; font-weight: 500; min-width: 52px; }
  .ldetail { font-size: 11px; color: var(--text-dim2); margin-left: auto; text-align: right; }

  /* Actions */
  .actions-row { padding: 10px 14px 0; }
  .act-btn {
    width: 100%; padding: 8px 13px;
    border-radius: var(--radius-sm); border: 1px solid var(--border);
    background: var(--bg2); color: var(--text-dim2);
    font-size: 12px; cursor: pointer;
    display: flex; align-items: center; justify-content: center; gap: 6px;
    transition: all 0.15s;
  }
  .act-btn:hover:not(:disabled) { color: var(--text); border-color: #3a3a44; background: var(--bg3); }
  .act-btn:disabled { opacity: 0.45; cursor: default; }

  /* Footer */
  .footer {
    margin-top: auto; padding: 10px 14px;
    border-top: 1px solid var(--border);
    display: flex; flex-direction: column; gap: 8px;
  }
  .footer-status { display: flex; align-items: center; gap: 7px; }
  .fdot { width: 6px; height: 6px; border-radius: 50%; background: var(--text-dim); transition: background 0.2s; }
  .fdot.on { background: var(--green); }
  .ftext { font-size: 11px; color: var(--text-dim); }

  .autostart-toggle {
    display: flex; align-items: center; gap: 6px;
    background: none; border: none; cursor: pointer;
    color: var(--text-dim2); font-size: 11px; padding: 0;
    width: 100%;
  }
  .autostart-toggle:hover { color: var(--text); }
  .autostart-toggle span.on { color: var(--text); }
  .toggle-pill {
    margin-left: auto;
    width: 28px; height: 16px; border-radius: 8px;
    background: var(--bg3); border: 1px solid var(--border);
    position: relative; transition: background 0.2s;
    flex-shrink: 0;
  }
  .toggle-pill::after {
    content: ''; position: absolute;
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--text-dim);
    top: 2px; left: 2px; transition: all 0.2s;
  }
  .toggle-pill.on { background: color-mix(in srgb, #4ade80 25%, var(--bg3)); border-color: color-mix(in srgb, #4ade80 40%, var(--border)); }
  .toggle-pill.on::after { background: var(--green); left: 14px; }

  /* Spinner */
  .spin {
    width: 12px; height: 12px; border-radius: 50%;
    border: 1.5px solid currentColor; border-top-color: transparent;
    animation: spin 0.6s linear infinite; display: inline-block;
  }
  .spin.sm { width: 10px; height: 10px; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
