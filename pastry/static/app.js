/* Pastry front end. Vanilla JavaScript, no dependencies.
 * User-supplied text is always inserted with textContent, never innerHTML. */
(() => {
  "use strict";

  const CSRF = document.body.dataset.csrf || "";
  const MIN_SECRET_LENGTH = 12;
  const MASK = "•".repeat(10);
  const THEME_KEY = "pastry-theme";

  const shell = document.getElementById("shell");
  const view = document.getElementById("view");
  const toolbar = document.getElementById("toolbar");
  const search = document.getElementById("search");
  const toastEl = document.getElementById("toast");

  const state = {
    entries: [],
    categories: [],
    listSpec: null,
    openEntryId: null,
    toastTimer: null,
    searchTimer: null,
    selected: new Set(),
    exportButton: null,
  };

  // ----- DOM helper -------------------------------------------------------

  function h(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "text") node.textContent = value;
      else if (key === "class") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (key === "value") node.value = value;
      else if (key === "checked") node.checked = Boolean(value);
      else if (value === true) node.setAttribute(key, "");
      else node.setAttribute(key, String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  // ----- API --------------------------------------------------------------

  class ApiError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }

  function redirectToLogin() {
    location.href = "/login?reason=expired";
  }

  async function fetchRaw(method, url, payload) {
    const headers = {};
    if (method !== "GET") headers["X-CSRF-Token"] = CSRF;
    let body;
    if (payload !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(payload);
    }
    try {
      return await fetch(url, { method, headers, body, credentials: "same-origin", cache: "no-store" });
    } catch (err) {
      throw new ApiError(0, "Cannot reach the Pastry server. Check that it is running.");
    }
  }

  async function request(method, url, payload) {
    const res = await fetchRaw(method, url, payload);
    if (res.status === 401) {
      redirectToLogin();
      throw new ApiError(401, "Your session has ended.");
    }
    if (res.status === 204) return null;
    const text = await res.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch (err) { data = null; }
    }
    if (!res.ok) {
      throw new ApiError(res.status, (data && data.detail) || `Request failed (${res.status}).`);
    }
    return data;
  }

  const api = {
    get: (url) => request("GET", url),
    post: (url, payload) => request("POST", url, payload),
    put: (url, payload) => request("PUT", url, payload),
    del: (url) => request("DELETE", url),
  };

  // ----- feedback ---------------------------------------------------------

  function toast(message) {
    toastEl.textContent = message;
    toastEl.hidden = false;
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => { toastEl.hidden = true; }, 2400);
  }

  async function copyText(value, label = "Copied") {
    if (!value) return toast("Nothing to copy");
    try {
      await navigator.clipboard.writeText(value);
    } catch (err) {
      // Fallback for browsers without the async clipboard API (non-secure origins).
      const area = h("textarea", { value, "aria-hidden": "true" });
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.append(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    toast(label);
  }

  function dialog({ title, message, confirmLabel = "Confirm", danger = false, input = null }) {
    return new Promise((resolve) => {
      const field = input
        ? h("input", { type: "password", autocomplete: "off", maxlength: "256", "aria-label": input.label })
        : null;
      const cancel = h("button", { class: "btn", type: "button", text: "Cancel" });
      const confirm = h("button", { class: `btn primary${danger ? " danger" : ""}`, type: "button", text: confirmLabel });
      const dlg = h(
        "dialog",
        { "aria-labelledby": "dialog-title" },
        h(
          "div",
          { class: "dialog-body" },
          h("h2", { id: "dialog-title", text: title }),
          message ? h("p", { text: message }) : null,
          field ? h("label", { class: "field" }, h("span", { text: input.label }), field) : null,
          h("div", { class: "dialog-actions" }, cancel, confirm),
        ),
      );
      let result = null;
      cancel.addEventListener("click", () => dlg.close());
      confirm.addEventListener("click", () => {
        if (field) {
          if (!field.value) { field.focus(); return; }
          result = field.value;
        } else {
          result = true;
        }
        dlg.close();
      });
      dlg.addEventListener("close", () => { dlg.remove(); resolve(result); });
      document.body.append(dlg);
      dlg.showModal();
      (field || confirm).focus();
    });
  }

  // ----- random passwords ------------------------------------------------

  function randomInt(n) {
    // Rejection sampling avoids modulo bias.
    const limit = Math.floor(0x100000000 / n) * n;
    let x;
    do {
      x = crypto.getRandomValues(new Uint32Array(1))[0];
    } while (x >= limit);
    return x % n;
  }

  const CHARSETS = {
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lower: "abcdefghijklmnopqrstuvwxyz",
    digits: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.?/",
  };

  function generatePassword(length, sets) {
    const chosen = Object.keys(CHARSETS).filter((key) => sets[key]);
    if (chosen.length === 0) throw new Error("Choose at least one character set.");
    const all = chosen.map((key) => CHARSETS[key]).join("");
    const out = chosen.map((key) => CHARSETS[key][randomInt(CHARSETS[key].length)]);
    while (out.length < length) out.push(all[randomInt(all.length)]);
    for (let i = out.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [out[i], out[j]] = [out[j], out[i]];
    }
    return { value: out.join(""), bits: Math.round(length * Math.log2(all.length)) };
  }

  // ----- navigation -------------------------------------------------------

  function setNavOpen(open) {
    shell.classList.toggle("nav-open", open);
    document.getElementById("scrim").hidden = !open;
    document.getElementById("menu-btn").setAttribute("aria-expanded", String(open));
  }

  function currentRoute() {
    const raw = location.hash.replace(/^#\/?/, "");
    return raw.split("/").filter(Boolean).map((part) => decodeURIComponent(part));
  }

  function highlightNav(head, arg) {
    document.querySelectorAll("[data-nav]").forEach((link) => link.removeAttribute("aria-current"));
    if (head === undefined) document.querySelector('[data-nav="all"]').setAttribute("aria-current", "page");
    if (head === "favourites") document.querySelector('[data-nav="favourites"]').setAttribute("aria-current", "page");
    if (head === "settings") document.querySelector('[data-nav="settings"]').setAttribute("aria-current", "page");
    if (head === "packages") document.querySelector('[data-nav="packages"]').setAttribute("aria-current", "page");
    if (head === "users") document.querySelector('[data-nav="users"]').setAttribute("aria-current", "page");
    if (head === "shared") document.querySelector('[data-nav="shared"]').setAttribute("aria-current", "page");
    if (head === "category") {
      document.querySelectorAll("#category-list a").forEach((link) => {
        if (link.dataset.category === arg) link.setAttribute("aria-current", "page");
      });
    }
  }

  async function lockEntry(id) {
    try {
      await api.post(`/api/entries/${id}/lock`);
    } catch (err) {
      // Locking is best-effort; the server also expires entry access with the session.
    }
  }

  async function route() {
    const [head, arg, sub] = currentRoute();
    const nextEntry = head === "entry" ? Number(arg) : null;
    if (state.openEntryId !== null && state.openEntryId !== nextEntry) {
      const previous = state.openEntryId;
      state.openEntryId = null;
      await lockEntry(previous);
    }
    state.openEntryId = nextEntry;
    highlightNav(head, arg);
    toolbar.hidden = ["settings", "packages", "users", "shared"].includes(head);
    setNavOpen(false);

    try {
      if (head === undefined) {
        state.listSpec = { title: "All entries", filter: () => true };
        await loadList();
      } else if (head === "favourites") {
        state.listSpec = { title: "Favourites", filter: (e) => e.favourite };
        await loadList();
      } else if (head === "category") {
        state.listSpec = { title: arg, filter: (e) => e.category === arg };
        await loadList();
      } else if (head === "new") {
        state.listSpec = null;
        await refreshCategories();
        await showEditor(null);
      } else if (head === "entry" && sub === "edit") {
        state.listSpec = null;
        await refreshCategories();
        await showEditor(nextEntry);
      } else if (head === "entry") {
        state.listSpec = null;
        await refreshCategories();
        await showDetail(nextEntry);
      } else if (head === "settings") {
        state.listSpec = null;
        await refreshCategories();
        await showSettings();
      } else if (head === "packages") {
        state.listSpec = null;
        await refreshCategories();
        await showPackages();
      } else if (head === "users") {
        state.listSpec = null;
        await refreshCategories();
        await showUsers();
      } else if (head === "shared") {
        state.listSpec = null;
        await refreshCategories();
        showShared();
      } else {
        location.hash = "#/";
      }
    } catch (err) {
      if (err.status !== 401) {
        view.replaceChildren(h("p", { class: "error", role: "alert", text: err.message }));
      }
    }
  }

  // ----- vault list -------------------------------------------------------

  async function loadList() {
    const query = search.value.trim();
    const data = await api.get(`/api/entries?q=${encodeURIComponent(query)}`);
    state.entries = data.entries;
    if (!query) updateCategories(data.entries);
    renderList(query);
  }

  // Sidebar categories and the editor's suggestions come from the full, unfiltered list.
  function updateCategories(entries) {
    state.categories = [...new Set(entries.map((e) => e.category).filter(Boolean))].sort((a, b) =>
      a.localeCompare(b),
    );
    renderCategories();
  }

  async function refreshCategories() {
    const data = await api.get("/api/entries");
    updateCategories(data.entries);
  }

  function renderCategories() {
    const container = document.getElementById("category-list");
    container.replaceChildren(
      ...state.categories.map((name) =>
        h("a", { href: `#/category/${encodeURIComponent(name)}`, "data-category": name, text: name }),
      ),
    );
    const head = currentRoute()[0];
    if (head === "category") highlightNav(head, currentRoute()[1]);
  }

  function renderList(query) {
    const spec = state.listSpec;
    const items = state.entries.filter(spec.filter).sort((a, b) => a.name.localeCompare(b.name));
    const countText = `${items.length} ${items.length === 1 ? "entry" : "entries"}`;
    let body;
    if (items.length === 0) {
      if (query) {
        body = h("div", { class: "empty" }, h("h2", { text: "No matches" }), h("p", { text: `Nothing matches "${query}".` }));
      } else if (spec.title === "All entries") {
        body = h(
          "div",
          { class: "empty" },
          h("h2", { text: "No entries yet" }),
          h("p", { text: "Add your first login, server or API key. Everything is encrypted before it is stored." }),
          h("a", { class: "btn primary", href: "#/new", text: "Add Entry" }),
        );
      } else {
        body = h("div", { class: "empty" }, h("h2", { text: "Nothing here yet" }), h("p", { text: "Entries you add will appear in this list." }));
      }
    } else {
      body = h("div", { class: "list" }, ...items.map(entryRow));
    }
    state.exportButton = h("button", { class: "btn small", type: "button", text: "Export as Pastry", onclick: () => openExport([...state.selected]) });
    view.replaceChildren(
      h(
        "div",
        { class: "view-head" },
        h("h1", { text: spec.title }),
        h("div", { class: "export-head" }, state.exportButton, h("span", { class: "muted small", text: countText })),
      ),
      body,
    );
    updateExportButton();
  }

  function entryRow(entry) {
    const box = h("input", { type: "checkbox", "aria-label": `Select ${entry.name} for export`, checked: state.selected.has(entry.id) });
    box.addEventListener("change", () => {
      if (box.checked) state.selected.add(entry.id);
      else state.selected.delete(entry.id);
      updateExportButton();
    });
    const link = h(
      "a",
      { class: "entry-main", href: `#/entry/${entry.id}` },
      h(
        "div",
        {},
        h(
          "div",
          { class: "entry-title" },
          entry.favourite ? h("span", { class: "star", "aria-label": "Favourite", text: "\u2605" }) : null,
          h("span", { text: entry.name }),
        ),
        h("div", { class: "entry-sub", text: entry.url || " " }),
      ),
      h(
        "div",
        { class: "entry-meta" },
        entry.locked ? h("span", { class: "badge", text: "Separate password" }) : null,
        entry.category ? h("span", { class: "badge", text: entry.category }) : null,
      ),
    );
    return h("div", { class: "entry-row" }, box, link);
  }

  function updateExportButton() {
    const btn = state.exportButton;
    if (!btn) return;
    const n = state.selected.size;
    btn.disabled = n === 0;
    btn.textContent = n ? `Export as Pastry (${n})` : "Export as Pastry";
  }

  // ----- entry details ----------------------------------------------------

  function formatDate(iso) {
    if (!iso) return "";
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
  }

  function secretRow(label, value, { secret = false, link = false } = {}) {
    let revealed = !secret;
    const valueEl = h("span", { class: "v mono" });
    const render = () => {
      if (!value) {
        valueEl.textContent = "—";
      } else if (link && /^https?:\/\//i.test(value)) {
        valueEl.replaceChildren(h("a", { href: value, rel: "noopener noreferrer", target: "_blank", text: value }));
      } else {
        valueEl.textContent = revealed ? value : MASK;
      }
    };
    render();
    const actions = [];
    if (secret && value) {
      const toggle = h("button", { class: "btn small", type: "button", text: "Show", "aria-label": `Show ${label}` });
      toggle.addEventListener("click", () => {
        revealed = !revealed;
        toggle.textContent = revealed ? "Hide" : "Show";
        render();
      });
      actions.push(toggle);
    }
    if (value) {
      actions.push(h("button", { class: "btn small", type: "button", text: "Copy", "aria-label": `Copy ${label}`, onclick: () => copyText(value) }));
    }
    return h("div", { class: "kv" }, h("div", { class: "k", text: label }), valueEl, h("div", { class: "actions" }, actions));
  }

  function lockedPanel(entry) {
    const errorEl = h("p", { class: "error", role: "alert", hidden: true });
    const input = h("input", { type: "password", autocomplete: "off", required: true, maxlength: "256", "aria-label": "Separate password" });
    const submit = h("button", { class: "btn primary", type: "submit", text: "Unlock entry" });
    const form = h(
      "form",
      {
        class: "locked-panel",
        onsubmit: async (event) => {
          event.preventDefault();
          if (!input.value) return;
          submit.disabled = true;
          errorEl.hidden = true;
          try {
            await api.post(`/api/entries/${entry.id}/unlock`, { password: input.value });
            await showDetail(entry.id);
          } catch (err) {
            if (err.status === 401) return;
            errorEl.textContent = err.message;
            errorEl.hidden = false;
            input.value = "";
            input.focus();
          } finally {
            submit.disabled = false;
          }
        },
      },
      h("p", { text: "This entry has its own separate password. Its username, password, notes and custom fields stay encrypted until you enter that password. Your vault password cannot open it." }),
      h("label", { class: "field" }, h("span", { text: "Separate password" }), input),
      errorEl,
      h("p", { class: "small", text: "If you lose this separate password, the protected data in this entry cannot be recovered." }),
      submit,
    );
    return h(
      "section",
      { class: "panel" },
      h("div", { class: "panel-head" }, h("h2", { text: "Locked" })),
      form,
    );
  }

  function contentPanel(entry) {
    const rows = [];
    if (entry.username) rows.push(secretRow("Username", entry.username));
    if (entry.password) rows.push(secretRow("Password", entry.password, { secret: true }));
    for (const field of entry.fields || []) {
      rows.push(secretRow(field.name || "Field", field.value, { secret: field.secret }));
    }
    if (entry.url) rows.push(secretRow("URL", entry.url, { link: true }));
    const sections = [
      h(
        "section",
        { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", { text: "Credentials" })),
        h(
          "div",
          { class: "panel-body" },
          rows.length ? rows : h("p", { class: "muted", text: "No credentials stored yet. Use Edit to add some." }),
        ),
      ),
    ];
    if (entry.notes) {
      sections.push(
        h(
          "section",
          { class: "panel" },
          h("div", { class: "panel-head" }, h("h2", { text: "Notes" })),
          h("div", { class: "panel-body" }, h("div", { class: "notes", text: entry.notes })),
        ),
      );
    }
    return sections;
  }

  async function showDetail(id) {
    const entry = await api.get(`/api/entries/${id}`);
    const locked = entry.locked && !entry.unlocked;
    const actions = [];
    if (!locked) actions.push(h("a", { class: "btn", href: `#/entry/${id}/edit`, text: "Edit" }));
    actions.push(h("button", { class: "btn", type: "button", text: "Export as Pastry", disabled: locked, onclick: () => openExport([id]) }));
    actions.push(h("button", { class: "btn danger", type: "button", text: "Delete", onclick: () => deleteEntry(entry) }));
    if (entry.locked && entry.unlocked) {
      actions.push(
        h("button", { class: "btn", type: "button", text: "Lock now", onclick: () => relock(entry.id) }),
        h("button", { class: "btn", type: "button", text: "Change separate password", onclick: () => changeSeparate(entry.id) }),
        h("button", { class: "btn", type: "button", text: "Remove separate password", onclick: () => removeSeparate(entry.id) }),
      );
    }

    const head = h(
      "div",
      { class: "detail-head" },
      h(
        "div",
        { class: "title-line" },
        entry.favourite ? h("span", { class: "star", "aria-label": "Favourite", text: "★" }) : null,
        h("h1", { text: entry.name }),
      ),
      entry.category ? h("div", { class: "muted small", text: entry.category }) : null,
      h("div", { class: "detail-actions" }, actions),
    );

    const body = locked ? [lockedPanel(entry)] : contentPanel(entry);
    view.replaceChildren(
      head,
      ...body,
      h("p", { class: "meta-foot", text: `Created ${formatDate(entry.created_at)} · Updated ${formatDate(entry.updated_at)}` }),
    );
  }

  async function relock(id) {
    await lockEntry(id);
    toast("Entry locked");
    await showDetail(id);
  }

  async function changeSeparate(id) {
    const value = await dialog({
      title: "Change separate password",
      message: `Choose a new separate password of at least ${MIN_SECRET_LENGTH} characters. The entry's protected data is re-encrypted with it.`,
      confirmLabel: "Change",
      input: { label: "New separate password" },
    });
    if (value === null) return;
    if (value.length < MIN_SECRET_LENGTH) return toast(`Use at least ${MIN_SECRET_LENGTH} characters`);
    try {
      await api.post(`/api/entries/${id}/protect/change`, { password: value });
      toast("Separate password changed");
      await showDetail(id);
    } catch (err) {
      toast(err.message);
    }
  }

  async function removeSeparate(id) {
    const confirmed = await dialog({
      title: "Remove separate password?",
      message: "The entry's contents will be protected by the vault password only. Entries you remove the lock from are no longer behind a second password.",
      confirmLabel: "Remove",
      danger: true,
    });
    if (!confirmed) return;
    try {
      await api.post(`/api/entries/${id}/protect/remove`);
      toast("Separate password removed");
      await showDetail(id);
    } catch (err) {
      toast(err.message);
    }
  }

  async function deleteEntry(entry) {
    const confirmed = await dialog({
      title: `Delete "${entry.name}"?`,
      message: "This permanently removes the entry. It cannot be undone.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!confirmed) return;
    try {
      await api.del(`/api/entries/${entry.id}`);
      state.openEntryId = null;
      toast("Entry deleted");
      location.hash = "#/";
    } catch (err) {
      toast(err.message);
    }
  }

  // ----- Export as Pastry ---------------------------------------------------

  const AFTER_OPEN_CHOICES = [["5", "5 minutes after opening"], ["15", "15 minutes after opening"],
    ["60", "1 hour after opening"], ["1440", "24 hours after opening"]];

  function packageStatusText(p) {
    const labels = { active: "Active", expired: "Expired", revoked: "Revoked", consumed: "Redeemed (one-time)" };
    if (p.policy === "after_open" && p.state === "active" && !p.expires_at) return "Active (not opened yet)";
    return labels[p.state] || p.state;
  }

  function policyText(p) {
    if (p.policy === "after_open") return `Window of ${Math.round((p.duration_seconds || 0) / 60)} min after opening`;
    if (p.policy === "absolute") return "Absolute deadline";
    return "One-time";
  }

  async function openExport(ids) {
    if (!ids.length) return toast("Select at least one entry");
    let timed = false;
    try {
      timed = Boolean((await api.get("/api/settings")).timed_packages);
    } catch (err) {
      if (err.status === 401) return;
    }
    const nameInput = h("input", { type: "text", maxlength: "100", value: "Credential package", "aria-label": "Package name" });
    const pwInput = h("input", { type: "password", maxlength: "256", autocomplete: "new-password", "aria-label": "Package password", class: "mono" });
    const pwRepeat = h("input", { type: "password", maxlength: "256", autocomplete: "new-password", "aria-label": "Repeat package password" });
    const genLength = h("input", { type: "range", min: "16", max: "48", value: "24", "aria-label": "Generated length" });
    const genOutput = h("output", { class: "small muted", text: "24" });
    genLength.addEventListener("input", () => { genOutput.textContent = genLength.value; });
    const generate = h("button", {
      class: "btn small", type: "button", text: "Generate",
      onclick: () => {
        const result = generatePassword(Number(genLength.value), { upper: true, lower: true, digits: true, symbols: true });
        pwInput.value = result.value;
        pwRepeat.value = result.value;
        pwInput.type = "text";
        pwRepeat.type = "text";
      },
    });
    const copyYes = h("input", { type: "radio", name: "allow-copy", value: "yes", checked: true });
    const copyNo = h("input", { type: "radio", name: "allow-copy", value: "no" });

    // Access type. Server-enforced choices need public_url to be configured on the server.
    const modeOffline = h("input", { type: "radio", name: "mode", value: "offline", checked: true });
    const modeAfter = h("input", { type: "radio", name: "mode", value: "after_open", disabled: !timed });
    const modeAbsolute = h("input", { type: "radio", name: "mode", value: "absolute", disabled: !timed });
    const modeOnce = h("input", { type: "radio", name: "mode", value: "one_time", disabled: !timed });
    const afterSelect = h("select", { "aria-label": "Window after opening" }, AFTER_OPEN_CHOICES.map(([v, t]) => h("option", { value: v, text: t })));
    const absoluteMinutes = h("input", { type: "number", min: "1", max: "43200", value: "120", "aria-label": "Deadline in minutes from now" });
    const offlineExpiry = h("select", { "aria-label": "Advisory expiry" }, [
      ["5", "5 minutes"], ["15", "15 minutes"], ["60", "1 hour"], ["1440", "24 hours"], ["10080", "7 days"],
    ].map(([v, t]) => h("option", { value: v, text: t })));
    offlineExpiry.value = "1440";
    const error = h("p", { class: "error", role: "alert", hidden: true });
    const dlg = h("dialog", { "aria-labelledby": "export-title" });
    const close = () => dlg.close();
    const selectedMode = () => document.querySelector("input[name=mode]:checked")?.value || "offline";

    function fail(message) {
      error.textContent = message;
      error.hidden = false;
    }

    async function submit() {
      error.hidden = true;
      if (!nameInput.value.trim()) return fail("Give the package a name.");
      if (pwInput.value.length < MIN_SECRET_LENGTH) return fail(`The package password needs at least ${MIN_SECRET_LENGTH} characters.`);
      if (pwInput.value !== pwRepeat.value) return fail("The package passwords do not match.");
      const mode = selectedMode();
      try {
        let res;
        if (mode === "offline") {
          res = await fetchRaw("POST", "/api/packages/export", {
            entry_ids: ids, name: nameInput.value.trim(), password: pwInput.value,
            allow_copy: copyYes.checked, access: "offline", expires_in_minutes: Number(offlineExpiry.value),
          });
        } else {
          const body = {
            entry_ids: ids, name: nameInput.value.trim(), password: pwInput.value, allow_copy: copyYes.checked,
            policy: mode,
            duration_minutes: mode === "after_open" ? Number(afterSelect.value) : null,
            absolute_minutes: mode === "absolute" ? Number(absoluteMinutes.value) : null,
          };
          res = await fetchRaw("POST", "/api/packages", body);
        }
        if (res.status === 401) return redirectToLogin();
        if (!res.ok) {
          let detail = `Export failed (${res.status}).`;
          try { detail = (await res.json()).detail || detail; } catch (err) { /* not JSON */ }
          return fail(detail);
        }
        const blob = await res.blob();
        const match = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") || "");
        const url = URL.createObjectURL(blob);
        const link = h("a", { href: url, download: match ? match[1] : "package.pastry" });
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
        close();
        toast(mode === "offline"
          ? "Package downloaded. Send its password through a different channel."
          : "Package created. It stays on this server and can be revoked from Packages.");
      } catch (err) {
        fail(err.message);
      }
    }

    dlg.append(h(
      "div",
      { class: "dialog-body export-body" },
      h("h2", { id: "export-title", text: `Export ${ids.length} ${ids.length === 1 ? "entry" : "entries"} as Pastry` }),
      h("p", { text: "The package is encrypted with its own password and contains only the entries listed here." }),
      h("label", { class: "field" }, h("span", { text: "Package name" }), nameInput),
      h("label", { class: "field" }, h("span", { text: "Package password (at least 12 characters)" }),
        h("div", { class: "input-with-action" }, pwInput, generate)),
      h("div", { class: "row-line" }, h("span", { class: "small", text: "Generator length" }), genLength, genOutput),
      h("label", { class: "field" }, h("span", { text: "Repeat package password" }), pwRepeat),
      h("fieldset", { class: "choice" }, h("legend", { text: "Allow copying in the viewer" }),
        h("label", {}, copyYes, "Yes"), h("label", {}, copyNo, "No")),
      h("fieldset", { class: "choice" }, h("legend", { text: "Access type" }),
        h("label", {}, modeOffline, "Offline encrypted file (opens without the server; expiry is advisory)"),
        h("div", { class: "indent" }, h("label", { class: "field" }, h("span", { text: "Advisory expiry" }), offlineExpiry)),
        h("label", { class: timed ? "" : "muted" }, modeAfter, "Expires after opening (server-enforced)"),
        h("div", { class: "indent" }, afterSelect),
        h("label", { class: timed ? "" : "muted" }, modeAbsolute, "Absolute deadline (server-enforced), minutes from now"),
        h("div", { class: "indent" }, absoluteMinutes),
        h("label", { class: timed ? "" : "muted" }, modeOnce, "One-time (the first successful open uses it up; server-enforced)")),
      timed ? null : h("p", { class: "warn", text: "Server-enforced packages need public_url in the server's config/pastry.json, set to the HTTPS address recipients use. The options are off until then." }),
      h("p", { class: "help", text: "Server-enforced packages cannot be opened if the server is unreachable. Revocation and expiry are enforced by the server clock. A recipient who has already opened a package may keep a copy of what they saw." }),
      error,
      h("div", { class: "dialog-actions" },
        h("button", { class: "btn", type: "button", text: "Cancel", onclick: close }),
        h("button", { class: "btn primary", type: "button", text: "Create package", onclick: submit })),
    ));
    dlg.addEventListener("close", () => {
      pwInput.value = "";
      pwRepeat.value = "";
      dlg.remove();
    });
    document.body.append(dlg);
    dlg.showModal();
    nameInput.focus();
  }

  // ----- Packages page ------------------------------------------------------

  async function showPackages() {
    const data = await api.get("/api/packages");
    const rows = data.packages.map((p) => {
      const actions = [];
      if (p.has_file) {
        actions.push(h("a", { class: "btn small", href: `/api/packages/${p.id}/file`, download: "", text: "Download" }));
      }
      if (p.state === "active") {
        actions.push(h("button", { class: "btn small", type: "button", text: "Revoke", onclick: () => revokePackage(p) }));
      }
      actions.push(h("button", { class: "btn small danger", type: "button", text: "Delete", onclick: () => deletePackage(p) }));
      return h(
        "div",
        { class: "kv pkg" },
        h("div", { class: "k" }, h("div", { text: p.name }), h("div", { class: "small muted", text: `${p.entry_count} entries · ${policyText(p)}` })),
        h("div", { class: "v plain" }, h("div", { text: `Created ${formatDate(p.created_at)}` }),
          h("div", { class: "small muted", text: p.expires_at ? `Expires ${formatDate(p.expires_at)}` : "No expiry yet" })),
        h("div", { class: "actions wrap" }, h("span", { class: "badge", text: packageStatusText(p) }), actions),
      );
    });
    view.replaceChildren(
      h("div", { class: "view-head" }, h("h1", { text: "Packages" }), h("span", { class: "muted small", text: `${data.packages.length} total` })),
      h("p", { class: "help", text: "Server-enforced packages are listed here. Revoke stops future releases. Delete removes the record and the stored copy. Passwords are never stored or shown again." }),
      rows.length ? h("div", { class: "panel" }, h("div", { class: "panel-body" }, rows)) : h("div", { class: "empty" }, h("h2", { text: "No packages yet" }), h("p", { text: "Select entries and choose Export as Pastry to create one." })),
    );
  }

  async function revokePackage(p) {
    const ok = await dialog({
      title: "Revoke this package?",
      message: "Recipients can no longer open it through the server. Copies already opened keep what the recipient saw. This cannot be undone.",
      confirmLabel: "Revoke",
      danger: true,
    });
    if (!ok) return;
    try {
      await api.post(`/api/packages/${p.id}/revoke`);
      toast("Package revoked");
      showPackages();
    } catch (err) {
      toast(err.message);
    }
  }

  async function deletePackage(p) {
    const ok = await dialog({
      title: "Delete this package record?",
      message: "The server removes the package, its release key and its stored copy. Files already downloaded are not affected.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del(`/api/packages/${p.id}`);
      toast("Package deleted");
      showPackages();
    } catch (err) {
      toast(err.message);
    }
  }

  // ----- Users (owner only) and Shared With Me ----------------------------------

  function formatShort(iso) {
    return iso ? formatDate(iso) : "";
  }

  async function showUsers() {
    const data = await api.get("/api/users");
    const rows = data.accounts.map((a) => {
      const actions = [];
      if (a.role !== "owner") {
        actions.push(h("button", {
          class: "btn small danger",
          type: "button",
          disabled: a.disabled,
          text: a.disabled ? "Disabled" : "Disable",
          onclick: () => disableAccount(a),
        }));
      }
      return h(
        "div",
        { class: "kv pkg" },
        h("div", { class: "k" }, h("div", { text: a.username })),
        h("div", { class: "v plain" }, h("div", { text: a.role === "owner" ? "Owner" : "Member" }),
          h("div", { class: "small muted", text: a.created_at ? `Created ${formatShort(a.created_at)}` : "Owner account" })),
        h("div", { class: "actions wrap" }, h("span", { class: "badge", text: a.disabled ? "disabled" : "active" }), actions),
      );
    });
    const usernameInput = h("input", { type: "text", maxlength: "64", autocomplete: "off", "aria-label": "Username for the new account" });
    const linkBox = h("div", { hidden: true, class: "invite-box" });
    const form = h(
      "form",
      {
        class: "inline-form",
        onsubmit: async (event) => {
          event.preventDefault();
          try {
            const result = await api.post("/api/users/invitations", { username: usernameInput.value.trim() });
            const link = `${location.origin}${result.path}`;
            linkBox.replaceChildren(
              h("p", { text: `Invitation for ${result.username}. It works once and expires in ${result.expires_in_hours} hours. The new user chooses their own master password.` }),
              h("p", { class: "mono invite-link", text: link }),
              h("button", { class: "btn small", type: "button", text: "Copy link", onclick: () => copyText(link, "Invitation link copied") }),
            );
            linkBox.hidden = false;
            usernameInput.value = "";
          } catch (err) {
            toast(err.message);
          }
        },
      },
      h("label", { class: "field" }, h("span", { text: "Create an invitation for a new account" }), usernameInput),
      h("button", { class: "btn", type: "submit", text: "Create invitation" }),
    );
    const pending = data.invitations.length
      ? h("p", { class: "help", text: `Pending invitations: ${data.invitations.length}. Each works once.` })
      : null;
    view.replaceChildren(
      h("div", { class: "view-head" }, h("h1", { text: "Users" }), h("span", { class: "muted small", text: `${data.accounts.length} ${data.accounts.length === 1 ? "account" : "accounts"}` })),
      h("p", { class: "help", text: "Each account has its own password and its own encrypted vault. You can manage accounts, but you cannot read another account's entries." }),
      h("div", { class: "panel" }, h("div", { class: "panel-body" }, rows)),
      h("section", { class: "editor-section" }, h("h2", { text: "Invite someone" }), form, linkBox, pending),
    );
  }

  async function disableAccount(account) {
    const ok = await dialog({
      title: `Disable ${account.username}?`,
      message: "They are signed out everywhere and cannot sign in. Their data stays encrypted on the server and is not deleted.",
      confirmLabel: "Disable",
      danger: true,
    });
    if (!ok) return;
    try {
      await api.post(`/api/users/${account.id}/disable`);
      toast("Account disabled");
      showUsers();
    } catch (err) {
      toast(err.message);
    }
  }

  function showShared() {
    view.replaceChildren(
      h("div", { class: "view-head" }, h("h1", { text: "Shared With Me" })),
      h("div", { class: "empty" },
        h("h2", { text: "Entry sharing is not available yet" }),
        h("p", { text: "Sharing one entry with another account needs recipient key verification and per-entry keys. Both are still in design, so sharing is switched off. Entries you create stay private to your account." }),
        h("p", { class: "small muted", text: "See docs/MULTIUSER-CRYPTO.md in the project for the reasons." }),
      ),
    );
  }

  // ----- editor -----------------------------------------------------------

  function blankEntry() {
    return { id: null, name: "", url: "", category: "", favourite: false, username: "", password: "", notes: "", fields: [], locked: false, unlocked: true };
  }

  async function showEditor(id) {
    let entry = blankEntry();
    if (id !== null) {
      entry = await api.get(`/api/entries/${id}`);
      if (entry.locked && !entry.unlocked) {
        view.replaceChildren(
          h(
            "section",
            { class: "panel" },
            h("div", { class: "panel-head" }, h("h2", { text: "Unlock to edit" })),
            h(
              "div",
              { class: "panel-body" },
              h("p", { class: "muted", text: "This entry has a separate password. Unlock it first, then edit it." }),
              h("a", { class: "btn", href: `#/entry/${id}`, text: "Back to entry" }),
            ),
          ),
        );
        return;
      }
    }

    const wasLocked = Boolean(entry.locked);
    const draft = (entry.fields || []).map((f) => ({ name: f.name, value: f.value, secret: f.secret }));
    const formError = h("p", { class: "error", role: "alert", hidden: true });

    const nameInput = h("input", { type: "text", required: true, maxlength: "200", autocomplete: "off", value: entry.name });
    const userInput = h("input", { type: "text", maxlength: "500", autocomplete: "off", autocapitalize: "off", spellcheck: "false", value: entry.username });
    const passwordInput = h("input", { type: "password", maxlength: "5000", autocomplete: "new-password", spellcheck: "false", value: entry.password, class: "mono" });
    const showButton = h("button", { class: "btn", type: "button", text: "Show" });
    showButton.addEventListener("click", () => {
      const visible = passwordInput.type === "text";
      passwordInput.type = visible ? "password" : "text";
      showButton.textContent = visible ? "Show" : "Hide";
    });
    const generatorPanel = h("div", { class: "generator", hidden: true });
    const generateButton = h("button", { class: "btn", type: "button", text: "Generate" });
    generateButton.addEventListener("click", () => {
      generatorPanel.hidden = false;
      regenerate();
    });
    const urlInput = h("input", { type: "url", maxlength: "2000", autocomplete: "off", value: entry.url });
    const categoryInput = h("input", { type: "text", maxlength: "100", autocomplete: "off", value: entry.category, list: "category-options" });
    const categoryOptions = h("datalist", { id: "category-options" }, state.categories.map((c) => h("option", { value: c })));
    const favouriteInput = h("input", { type: "checkbox", checked: entry.favourite });
    const notesInput = h("textarea", { maxlength: "10000", text: entry.notes });

    // Password generator
    const lengthInput = h("input", { type: "range", min: "8", max: "64", value: "24", "aria-label": "Password length" });
    const lengthOutput = h("output", { text: "24" });
    const setBoxes = Object.keys(CHARSETS).map((key) => ({
      key,
      box: h("input", { type: "checkbox", checked: true }),
      label: { upper: "Uppercase", lower: "Lowercase", digits: "Digits", symbols: "Symbols" }[key],
    }));
    const strengthOutput = h("output", { class: "small muted" });
    function regenerate() {
      const sets = Object.fromEntries(setBoxes.map((s) => [s.key, s.box.checked]));
      try {
        const result = generatePassword(Number(lengthInput.value), sets);
        passwordInput.value = result.value;
        passwordInput.type = "text";
        showButton.textContent = "Hide";
        strengthOutput.textContent = `About ${result.bits} bits of entropy`;
      } catch (err) {
        strengthOutput.textContent = err.message;
      }
    }
    lengthInput.addEventListener("input", () => {
      lengthOutput.textContent = lengthInput.value;
    });
    lengthInput.addEventListener("change", regenerate);
    setBoxes.forEach((s) => s.box.addEventListener("change", regenerate));
    generatorPanel.append(
      h("div", { class: "row-line" }, h("span", { class: "small", text: "Length" }), lengthInput, lengthOutput),
      h("div", { class: "opts" }, setBoxes.map((s) => h("label", {}, s.box, s.label))),
      h(
        "div",
        { class: "row-line" },
        h("button", { class: "btn small", type: "button", text: "Regenerate", onclick: regenerate }),
        strengthOutput,
      ),
    );

    // Custom fields
    const fieldList = h("div", { class: "fields" });
    function renderFields() {
      fieldList.replaceChildren(
        ...draft.map((field, index) => customFieldRow(field, index)),
      );
      if (draft.length === 0) {
        fieldList.append(h("p", { class: "muted small", text: "No custom fields. Add SSH passwords, recovery codes, API keys or notes here." }));
      }
    }
    function customFieldRow(field, index) {
      const nameEl = h("input", { type: "text", maxlength: "100", placeholder: "Field name, e.g. SSH Password", "aria-label": "Field name", value: field.name });
      nameEl.addEventListener("input", () => { field.name = nameEl.value; });
      const valueEl = h("input", { type: field.secret ? "password" : "text", maxlength: "5000", autocomplete: "off", spellcheck: "false", "aria-label": "Field value", value: field.value });
      valueEl.addEventListener("input", () => { field.value = valueEl.value; });
      const typeEl = h("select", { "aria-label": "Field type" }, h("option", { value: "text", text: "Text" }), h("option", { value: "secret", text: "Masked secret" }));
      typeEl.value = field.secret ? "secret" : "text";
      typeEl.addEventListener("change", () => {
        field.secret = typeEl.value === "secret";
        valueEl.type = field.secret ? "password" : "text";
      });
      const reveal = h("button", { class: "btn small", type: "button", text: "Show", "aria-label": "Show field value" });
      reveal.addEventListener("click", () => {
        const show = valueEl.type === "password";
        valueEl.type = show ? "text" : "password";
        reveal.textContent = show ? "Hide" : "Show";
      });
      const move = (delta) => {
        const target = index + delta;
        if (target < 0 || target >= draft.length) return;
        [draft[index], draft[target]] = [draft[target], draft[index]];
        renderFields();
      };
      return h(
        "div",
        { class: "custom-field" },
        h("label", { class: "field" }, h("span", { text: "Name" }), nameEl),
        h("label", { class: "field" }, h("span", { text: "Value" }), valueEl),
        h(
          "div",
          { class: "cf-controls" },
          h("div", { class: "group" }, typeEl, reveal),
          h(
            "div",
            { class: "group" },
            h("button", { class: "btn small", type: "button", text: "Up", "aria-label": "Move field up", onclick: () => move(-1), disabled: index === 0 }),
            h("button", { class: "btn small", type: "button", text: "Down", "aria-label": "Move field down", onclick: () => move(1), disabled: index === draft.length - 1 }),
            h("button", { class: "btn small danger", type: "button", text: "Remove", onclick: () => { draft.splice(index, 1); renderFields(); } }),
          ),
        ),
      );
    }
    const addFieldButton = h("button", {
      class: "btn",
      type: "button",
      text: "Add Field",
      onclick: () => {
        draft.push({ name: "", value: "", secret: false });
        renderFields();
        fieldList.querySelector("input")?.focus();
      },
    });
    renderFields();

    // Separate password
    const lockBox = h("input", { type: "checkbox", checked: wasLocked });
    const sepFirst = h("input", { type: "password", autocomplete: "new-password", maxlength: "256", "aria-label": "Separate password" });
    const sepSecond = h("input", { type: "password", autocomplete: "new-password", maxlength: "256", "aria-label": "Repeat separate password" });
    const sepBlock = h(
      "div",
      { hidden: !lockBox.checked || wasLocked },
      h("div", { class: "warn", text: "Losing a separate password makes that entry's protected data unrecoverable. Store it somewhere safe, separate from the vault password." }),
      h("label", { class: "field" }, h("span", { text: `Separate password (at least ${MIN_SECRET_LENGTH} characters)` }), sepFirst),
      h("label", { class: "field" }, h("span", { text: "Repeat separate password" }), sepSecond),
    );
    lockBox.addEventListener("change", () => {
      sepBlock.hidden = !lockBox.checked || wasLocked;
    });
    const lockNote = wasLocked
      ? "This entry is protected. Unchecking the box and saving removes the separate password."
      : "When enabled, this entry's contents are encrypted with a second password that the vault password cannot open.";

    const cancelHref = id === null ? "#/" : `#/entry/${id}`;
    const form = h(
      "form",
      { class: "editor", novalidate: true },
      h("h1", { text: id === null ? "New entry" : "Edit entry" }),
      h(
        "section",
        { class: "editor-section" },
        h("label", { class: "field" }, h("span", { text: "Entry name" }), nameInput),
        h("label", { class: "field" }, h("span", { text: "Username or email" }), userInput),
        h(
          "label",
          { class: "field" },
          h("span", { text: "Password" }),
          h("div", { class: "input-with-action" }, passwordInput, showButton, generateButton),
        ),
        generatorPanel,
        h("label", { class: "field" }, h("span", { text: "URL (optional)" }), urlInput),
        h("label", { class: "field" }, h("span", { text: "Category" }), categoryInput, categoryOptions),
        h("label", { class: "check" }, favouriteInput, h("span", { text: "Mark as favourite" })),
        h("label", { class: "field" }, h("span", { text: "Notes (optional)" }), notesInput),
      ),
      h(
        "section",
        { class: "editor-section" },
        h("h2", { text: "Custom fields" }),
        h("p", { class: "help", text: "Add as many fields as you need. Mark sensitive values as a masked secret." }),
        fieldList,
        h("div", {}, addFieldButton),
      ),
      h(
        "section",
        { class: "editor-section" },
        h("h2", { text: "Separate password" }),
        h("label", { class: "check" }, lockBox, h("span", { text: "Require Separate Password" })),
        h("p", { class: "help", text: lockNote }),
        sepBlock,
      ),
      formError,
      h(
        "div",
        { class: "form-actions" },
        h("a", { class: "btn", href: cancelHref, text: "Cancel" }),
        h("button", { class: "btn primary", type: "submit", text: "Save" }),
      ),
    );

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      formError.hidden = true;
      const fail = (message) => {
        formError.textContent = message;
        formError.hidden = false;
      };
      const name = nameInput.value.trim();
      if (!name) return fail("Enter a name for this entry.");
      const lockOn = lockBox.checked;
      if (lockOn && !wasLocked) {
        if (sepFirst.value.length < MIN_SECRET_LENGTH) return fail(`The separate password needs at least ${MIN_SECRET_LENGTH} characters.`);
        if (sepFirst.value !== sepSecond.value) return fail("The separate passwords do not match.");
      }
      if (!lockOn && wasLocked) {
        const confirmed = await dialog({
          title: "Remove separate password?",
          message: "Saving will store this entry's contents under the vault password only.",
          confirmLabel: "Remove and save",
          danger: true,
        });
        if (!confirmed) return;
      }

      const payload = {
        name,
        url: urlInput.value.trim(),
        category: categoryInput.value.trim(),
        favourite: favouriteInput.checked,
        username: userInput.value,
        password: passwordInput.value,
        notes: notesInput.value,
        fields: draft.map((f) => ({ name: f.name.trim(), value: f.value, secret: f.secret })).filter((f) => f.name),
      };
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        if (id === null) {
          if (lockOn) payload.separate_password = sepFirst.value;
          const created = await api.post("/api/entries", payload);
          toast(lockOn ? "Saved. Enter the separate password to view it." : "Entry saved");
          location.hash = `#/entry/${created.id}`;
        } else {
          await api.put(`/api/entries/${id}`, payload);
          if (lockOn && !wasLocked) await api.post(`/api/entries/${id}/protect/enable`, { password: sepFirst.value });
          if (!lockOn && wasLocked) await api.post(`/api/entries/${id}/protect/remove`);
          toast("Entry saved");
          location.hash = `#/entry/${id}`;
        }
      } catch (err) {
        if (err.status !== 401) fail(err.message);
      } finally {
        submit.disabled = false;
      }
    });

    view.replaceChildren(form);
    nameInput.focus();
  }

  // ----- settings ---------------------------------------------------------

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme === "dark" ? "dark" : "light";
  }

  function savedTheme() {
    try {
      return localStorage.getItem(THEME_KEY) || "light";
    } catch (err) {
      return "light";
    }
  }

  function saveTheme(theme) {
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch (err) {
      // Storage may be blocked; the choice then lasts for this page only.
    }
  }

  function formatWhen(epochSeconds) {
    return new Date(epochSeconds * 1000).toLocaleString();
  }

  function sessionsSection(sessionData) {
    const rows = sessionData.sessions.map((s) =>
      h(
        "div",
        { class: "kv" },
        h("div", { class: "k", text: s.current ? "This session" : "Other session" }),
        h("div", { class: "v plain", text: `Signed in ${formatWhen(s.created)} \u00b7 last active ${formatWhen(s.last_seen)}` }),
        h("div", { class: "actions" }, h("button", {
          class: "btn small danger",
          type: "button",
          text: s.current ? "Sign out" : "Revoke",
          onclick: async () => {
            const confirmed = await dialog({
              title: s.current ? "Sign out this session?" : "Revoke this session?",
              message: "The device using it is signed out immediately.",
              confirmLabel: s.current ? "Sign out" : "Revoke",
              danger: true,
            });
            if (!confirmed) return;
            try {
              await api.del(`/api/sessions/${s.id}`);
              if (s.current) return signOutNow();
              toast("Session revoked");
              showSettings();
            } catch (err) {
              toast(err.message);
            }
          },
        })),
      ),
    );
    const others = sessionData.sessions.filter((s) => !s.current).length;
    const logOutOthers = h("button", {
      class: "btn",
      type: "button",
      text: "Log out other sessions",
      disabled: others === 0,
      onclick: async () => {
        const confirmed = await dialog({
          title: "Log out other sessions?",
          message: "Every other device will be signed out. This session stays signed in.",
          confirmLabel: "Log out others",
          danger: true,
        });
        if (!confirmed) return;
        try {
          const result = await api.post("/api/sessions/revoke-others");
          toast(`Signed out ${result.revoked} other session(s)`);
          showSettings();
        } catch (err) {
          toast(err.message);
        }
      },
    });
    return h(
      "section",
      {},
      h("h2", { text: "Active sessions" }),
      h("p", { text: "Each signed-in browser is listed. Revoking a session takes effect on its next request." }),
      h("div", { class: "panel" }, h("div", { class: "panel-body" }, rows)),
      h("div", { class: "form-actions" }, logOutOthers),
    );
  }

  function passwordSection() {
    const current = h("input", { type: "password", autocomplete: "current-password", maxlength: "256", "aria-label": "Current master password" });
    const next = h("input", { type: "password", autocomplete: "new-password", maxlength: "256", "aria-label": "New master password" });
    const repeat = h("input", { type: "password", autocomplete: "new-password", maxlength: "256", "aria-label": "Repeat new master password" });
    const error = h("p", { class: "error", role: "alert", hidden: true });
    const form = h(
      "form",
      {
        onsubmit: async (event) => {
          event.preventDefault();
          error.hidden = true;
          if (next.value.length < MIN_SECRET_LENGTH) {
            error.textContent = `The new password needs at least ${MIN_SECRET_LENGTH} characters.`;
            error.hidden = false;
            return;
          }
          if (next.value !== repeat.value) {
            error.textContent = "The new passwords do not match.";
            error.hidden = false;
            return;
          }
          try {
            await api.post("/api/account/password", { current: current.value, new: next.value });
            location.href = "/login?reason=password";
          } catch (err) {
            if (err.status === 401) return;
            error.textContent = err.message;
            error.hidden = false;
          }
        },
      },
      h("label", { class: "field" }, h("span", { text: "Current master password" }), current),
      h("label", { class: "field" }, h("span", { text: "New master password" }), next),
      h("label", { class: "field" }, h("span", { text: "Repeat new master password" }), repeat),
      error,
      h("p", { class: "help", text: "Changing the password signs out every session, including this one. Entries are not re-encrypted and stay accessible." }),
      h("button", { class: "btn", type: "submit", text: "Change password" }),
    );
    return h("section", {}, h("h2", { text: "Change password" }), form);
  }

  function backupSection(settings) {
    const b = settings.backups;
    const status = b.latest
      ? `Latest backup: ${b.latest} (${formatDate(b.latest_at)}). ${b.count} kept in the backups folder.`
      : "No backups yet on this server.";
    return h(
      "section",
      {},
      h("h2", { text: "Backup status" }),
      h("p", { text: status }),
      h(
        "p",
        {},
        "Create a backup on the server with ",
        h("span", { class: "code", text: "pastry backup" }),
        ", and check it with ",
        h("span", { class: "code", text: "pastry backup verify FILE" }),
        ".",
      ),
    );
  }

  async function showSettings() {
    const settings = await api.get("/api/settings");
    const sessionData = await api.get("/api/sessions");
    const theme = savedTheme();

    const themeInputs = ["light", "dark"].map((value) =>
      h("label", {}, h("input", { type: "radio", name: "theme", value, checked: theme === value }), value === "light" ? "Light" : "Dark"),
    );
    themeInputs.forEach((label) => label.querySelector("input").addEventListener("change", (event) => {
      applyTheme(event.target.value);
      saveTheme(event.target.value);
    }));

    const timeoutInput = h("input", { type: "number", min: "1", max: "120", step: "1", value: String(settings.session_timeout_minutes), "aria-label": "Session timeout in minutes" });
    const timeoutForm = h(
      "form",
      { class: "inline-form" },
      h("label", { class: "field" }, h("span", { text: "Lock after inactivity (minutes)" }), timeoutInput),
      h("button", { class: "btn", type: "submit", text: "Save" }),
    );
    timeoutForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const minutes = Number(timeoutInput.value);
        const updated = await api.put("/api/settings", { session_timeout_minutes: minutes });
        toast(`Session will lock after ${updated.session_timeout_minutes} minutes of inactivity`);
      } catch (err) {
        toast(err.message);
      }
    });

    const exportPass = h("input", { type: "password", autocomplete: "new-password", maxlength: "256", "aria-label": "Export passphrase" });
    const exportButton = h("button", { class: "btn", type: "button", text: "Download encrypted export" });
    exportButton.addEventListener("click", async () => {
      if (exportPass.value.length < MIN_SECRET_LENGTH) return toast(`Use a passphrase of at least ${MIN_SECRET_LENGTH} characters`);
      try {
        const res = await fetchRaw("POST", "/api/export", { passphrase: exportPass.value });
        if (res.status === 401) return redirectToLogin();
        if (!res.ok) throw new ApiError(res.status, "Export failed.");
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const link = h("a", { href: url, download: "pastry-export.json" });
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
        exportPass.value = "";
        toast("Export downloaded");
      } catch (err) {
        toast(err.message);
      }
    });

    const importFile = h("input", { type: "file", accept: "application/json,.json", "aria-label": "Export file" });
    const importPass = h("input", { type: "password", autocomplete: "off", maxlength: "256", "aria-label": "Import passphrase" });
    const importButton = h("button", { class: "btn", type: "button", text: "Import" });
    importButton.addEventListener("click", async () => {
      const file = importFile.files[0];
      if (!file) return toast("Choose an export file first");
      if (!importPass.value) return toast("Enter the export passphrase");
      try {
        const data = await file.text();
        const result = await api.post("/api/import", { passphrase: importPass.value, data });
        importPass.value = "";
        toast(`Imported ${result.imported} entries (${result.skipped} already present)`);
        location.hash = "#/";
      } catch (err) {
        toast(err.message);
      }
    });

    const signOut = h("button", { class: "btn", type: "button", text: "Lock and sign out" });
    signOut.addEventListener("click", signOutNow);

    view.replaceChildren(
      h(
        "div",
        { class: "settings" },
        h("h1", { text: "Settings" }),
        h(
          "section",
          {},
          h("h2", { text: "Appearance" }),
          h("p", { text: "Light is the default. The choice is remembered in this browser only." }),
          h("div", { class: "radio-row" }, themeInputs),
        ),
        h(
          "section",
          {},
          h("h2", { text: "Session" }),
          h("p", { text: "Pastry locks automatically after this much inactivity. Locking clears the vault key from memory." }),
          timeoutForm,
        ),
        h(
          "section",
          {},
          h("h2", { text: "Account" }),
          h("p", { text: `Signed in as ${settings.username}.` }),
          h(
            "p",
            {},
            "To change the username, run ",
            h("span", { class: "code", text: "pastry admin set-username" }),
            " on the server. To change the master password, run ",
            h("span", { class: "code", text: "pastry admin set-password" }),
            ". Both sign out all current sessions.",
          ),
        ),
        h(
          "section",
          {},
          h("h2", { text: "Backup and export" }),
          h(
            "p",
            {},
            "On the server, ",
            h("span", { class: "code", text: "pastry backup" }),
            " writes an archive of the encrypted database and config. It needs the master password to be used.",
          ),
          h(
            "p",
            { text: "An encrypted export is a file you can keep elsewhere. It is protected by the passphrase below. Entries that have a separate password remain protected inside it. Passwords you choose here are never stored on the server." },
          ),
          h("label", { class: "field" }, h("span", { text: "Export passphrase (at least 12 characters)" }), exportPass),
          h("div", { class: "form-actions" }, exportButton),
          h("hr"),
          h("label", { class: "field" }, h("span", { text: "Export file" }), importFile),
          h("label", { class: "field" }, h("span", { text: "Export passphrase" }), importPass),
          h("div", { class: "form-actions" }, importButton),
        ),
        sessionsSection(sessionData),
        passwordSection(),
        backupSection(settings),
        h("section", {}, h("h2", { text: "Sign out" }), h("p", { text: "Clears this session and the vault key from memory." }), signOut),
      ),
    );
  }

  async function signOutNow() {
    try {
      await api.post("/api/logout");
    } catch (err) {
      // Even if the request failed, leave the vault page.
    }
    location.href = "/login";
  }

  // ----- boot -------------------------------------------------------------

  function pollSession() {
    // Only checks status; it does not extend the session.
    fetch("/api/session/status", { cache: "no-store", credentials: "same-origin" })
      .then((res) => { if (res.status === 401) redirectToLogin(); })
      .catch(() => {});
  }

  function boot() {
    applyTheme(savedTheme());
    if (document.body.dataset.role !== "owner") {
      document.querySelectorAll("[data-owner-only]").forEach((link) => { link.hidden = true; });
    }
    document.getElementById("menu-btn").addEventListener("click", () => {
      setNavOpen(!shell.classList.contains("nav-open"));
    });
    document.getElementById("scrim").addEventListener("click", () => setNavOpen(false));
    document.getElementById("signout-btn").addEventListener("click", signOutNow);
    search.addEventListener("input", () => {
      clearTimeout(state.searchTimer);
      state.searchTimer = setTimeout(() => {
        if (state.listSpec) loadList().catch(() => {});
      }, 180);
    });
    window.addEventListener("hashchange", route);
    setInterval(pollSession, 30000);
    if (!location.hash) location.hash = "#/";
    route();
  }

  boot();
})();
