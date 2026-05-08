// Vulnerable demo SPA — uses innerHTML on comment bodies on purpose.

const state = {
    token: localStorage.getItem("token") || null,
    username: localStorage.getItem("username") || null,
};

const $ = (sel) => document.querySelector(sel);

function setAuthUI() {
    const signedIn = !!state.token;
    $("#auth-section").hidden = signedIn;
    $("#wall-section").hidden = !signedIn;
    $("#logout-btn").hidden = !signedIn;
    $("#who").textContent = signedIn
        ? `signed in as ${state.username}`
        : "not signed in";
}

async function api(path, opts = {}) {
    const res = await fetch(path, {
        headers: {"Content-Type": "application/json"},
        ...opts,
    });
    let data;
    try {
        data = await res.json();
    } catch {
        data = {error: `non-json response (${res.status})`};
    }
    return {ok: res.ok, status: res.status, data};
}

async function loadComments(q = "") {
    const url = q
        ? `/api/comments?q=${encodeURIComponent(q)}`
        : "/api/comments";
    const {ok, data} = await api(url);
    const list = $("#comments");
    list.innerHTML = "";
    $("#search-debug").textContent = data.query
        ? `executed: ${data.query}`
        : "";
    if (!ok) {
        list.innerHTML = `<li class="error">${data.error || "error"}</li>`;
        return;
    }
    for (const c of data.comments) {
        const li = document.createElement("li");
        li.className = "comment";
        // VULNERABLE: rendering server-stored body as HTML -> stored XSS.
        li.innerHTML = `
            <div class="meta"><b>${escapeText(c.username)}</b>
              <span class="ts">${escapeText(c.created_at || "")}</span></div>
            <div class="body">${c.body}</div>`;
        list.appendChild(li);
    }
}

// Used only for username/timestamp. Comment body is intentionally NOT escaped.
function escapeText(s) {
    return String(s).replace(/[&<>"']/g, (ch) => (
        {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[ch]
    ));
}

// ---- handlers ----

$("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const {ok, data} = await api("/api/login", {
        method: "POST",
        body: JSON.stringify({
            username: fd.get("username"),
            password: fd.get("password"),
        }),
    });
    $("#login-debug").textContent = data.query
        ? `executed: ${data.query}`
        : "";
    if (!ok) {
        $("#login-debug").textContent +=
            `\nerror: ${data.error || "login failed"}`;
        return;
    }
    state.token = data.token;
    state.username = data.username;
    localStorage.setItem("token", state.token);
    localStorage.setItem("username", state.username);
    setAuthUI();
    loadComments();
});

$("#register-btn").addEventListener("click", async () => {
    const fd = new FormData($("#login-form"));
    const username = fd.get("username");
    const password = fd.get("password");
    if (!username || !password) {
        $("#login-debug").textContent = "fill in username + password first";
        return;
    }
    const {ok, data} = await api("/api/register", {
        method: "POST",
        body: JSON.stringify({username, password}),
    });
    $("#login-debug").textContent = ok
        ? `registered ${data.username} — now sign in`
        : `error: ${data.error}`;
});

$("#logout-btn").addEventListener("click", () => {
    state.token = null;
    state.username = null;
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    setAuthUI();
});

$("#comment-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const {ok, data} = await api("/api/comments", {
        method: "POST",
        body: JSON.stringify({token: state.token, body: fd.get("body")}),
    });
    if (!ok) {
        alert(data.error || "post failed");
        return;
    }
    e.target.reset();
    loadComments();
});

$("#search-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const q = new FormData(e.target).get("q") || "";
    loadComments(q);
});

$("#clear-search").addEventListener("click", () => {
    $("#search-form").reset();
    loadComments();
});

// init
setAuthUI();
if (state.token) loadComments();
