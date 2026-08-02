/* Console helpers — original work for aauth-java-person-server (see docs/UI-CONTRACT.md). */

"use strict";

const TOKEN_KEY = document.documentElement.dataset.tokenKey || "aauth-java.console.token";

function getToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}

function setToken(value) {
  if (value) {
    localStorage.setItem(TOKEN_KEY, value);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

/**
 * Fetch wrapper: adds the bearer token, JSON-encodes object bodies, and turns
 * non-2xx responses into errors carrying the server's `detail` /
 * `error_description` message (see docs/UI-CONTRACT.md, error body shape).
 */
async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers);
  const token = getToken();
  if (token && !options.noAuth) {
    headers["Authorization"] = "Bearer " + token;
  }
  let body = options.body;
  if (body !== undefined && typeof body !== "string") {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(body);
  }
  const response = await fetch(path, Object.assign({}, options, { headers, body }));
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!response.ok) {
    let message = text;
    if (data && typeof data === "object") {
      message = data.detail || data.error_description || data.error || text;
    }
    throw new Error(response.status + " — " + (message || response.statusText));
  }
  return data;
}

/** DOM builder: el("td", {class: "mono"}, child, ...). Arrays are flattened. */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined) {
      continue;
    }
    if (key === "class") {
      node.className = value;
    } else if (key.startsWith("on")) {
      node.addEventListener(key.slice(2), value);
    } else {
      node.setAttribute(key, value);
    }
  }
  for (const child of children.flat(2)) {
    if (child !== null && child !== undefined) {
      node.append(child.nodeType ? child : document.createTextNode(String(child)));
    }
  }
  return node;
}

function dataTable(headers, rows) {
  const bodyRows = rows.length
    ? rows
    : [el("tr", {}, el("td", { class: "empty", colspan: String(headers.length) }, "Nothing here yet."))];
  return el(
    "table",
    { class: "data" },
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, bodyRows),
  );
}

function pill(value) {
  const text = value === null || value === undefined || value === "" ? "—" : String(value);
  return el("span", { class: "pill " + text.toLowerCase() }, text);
}

function shortId(value, length = 12) {
  const text = String(value ?? "");
  return text.length > length ? text.slice(0, length) + "…" : text;
}

let bannerTimer = null;

function banner(message, isError = false) {
  document.querySelectorAll(".banner").forEach((node) => node.remove());
  const node = el("div", { class: isError ? "banner error" : "banner" }, message);
  document.body.append(node);
  clearTimeout(bannerTimer);
  bannerTimer = setTimeout(() => node.remove(), isError ? 8000 : 4000);
}

/** Run an async action, surface failures in the banner, and rerender via refresh(). */
async function act(action, refresh) {
  try {
    await action();
    if (refresh) {
      await refresh();
    }
  } catch (error) {
    banner(error.message, true);
  }
}

/** Wire the top-bar token input to localStorage. */
function initTokenBox() {
  const input = document.querySelector(".tokenbox input");
  if (!input) {
    return;
  }
  input.value = getToken();
  input.addEventListener("change", () => {
    setToken(input.value.trim());
    banner(input.value.trim() ? "Token saved." : "Token cleared.");
    document.dispatchEvent(new CustomEvent("token-changed"));
  });
}

/** Tab strip: buttons carry data-panel ids; loaders run when a panel activates. */
function initTabs(loaders) {
  const buttons = [...document.querySelectorAll(".tabs button")];
  function activate(name) {
    for (const button of buttons) {
      button.classList.toggle("active", button.dataset.panel === name);
    }
    for (const panel of document.querySelectorAll("[data-panel-body]")) {
      panel.hidden = panel.dataset.panelBody !== name;
    }
    if (loaders[name]) {
      loaders[name]().catch((error) => banner(error.message, true));
    }
  }
  for (const button of buttons) {
    button.addEventListener("click", () => activate(button.dataset.panel));
  }
  document.addEventListener("token-changed", () => {
    const current = buttons.find((b) => b.classList.contains("active"));
    if (current) {
      activate(current.dataset.panel);
    }
  });
  if (buttons.length) {
    activate(buttons[0].dataset.panel);
  }
}
