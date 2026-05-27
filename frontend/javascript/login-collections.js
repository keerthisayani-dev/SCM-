function resolveApiBaseUrl() {
    const { protocol, hostname, port, origin } = window.location;
    const isHttpOrigin = protocol === "http:" || protocol === "https:";
    const isLocalhost = hostname === "127.0.0.1" || hostname === "localhost";

    if (isHttpOrigin && isLocalhost && port) {
        return origin;
    }

    return "http://127.0.0.1:8002";
}

const API_BASE_URL = resolveApiBaseUrl();
const refreshButton = document.getElementById("refresh-login-collections");
const statusMessage = document.getElementById("status-message");
const loginCollectionsBody = document.getElementById("login-collections-body");
const browserSessionStatus = document.getElementById("browser-session-status");
const browserSessionGrid = document.getElementById("browser-session-grid");
const browserSessionUserId = document.getElementById("browser-session-user-id");
const browserSessionEmail = document.getElementById("browser-session-email");
const browserSessionRole = document.getElementById("browser-session-role");
const browserSessionSavedAt = document.getElementById("browser-session-saved-at");

function setStatus(message, type = "") {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`.trim();
}

function formatValue(value) {
    if (value === null || value === undefined || value === "") {
        return "Not available";
    }

    return String(value);
}

function formatDate(value) {
    if (!value) {
        return "Not available";
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return String(value);
    }

    return parsed.toLocaleString();
}

function renderBrowserSession() {
    const session = window.authStorage.loadAuthSession();
    if (!session || !session.user) {
        browserSessionGrid.hidden = true;
        browserSessionStatus.textContent = "No saved login session was found in this browser.";
        return;
    }

    browserSessionUserId.textContent = formatValue(session.user.id);
    browserSessionEmail.textContent = formatValue(session.user.email);
    browserSessionRole.textContent = formatValue(session.user.role);
    browserSessionSavedAt.textContent = formatDate(session.savedAt);
    browserSessionGrid.hidden = false;
    browserSessionStatus.textContent = "Saved login session found in this browser.";
}

function renderRows(items) {
    if (!Array.isArray(items) || items.length === 0) {
        loginCollectionsBody.innerHTML = '<tr><td colspan="7">No stored login details were found.</td></tr>';
        return;
    }

    loginCollectionsBody.innerHTML = items.map((item) => `
        <tr>
            <td>${formatValue(item.id)}</td>
            <td>${formatValue(item.user_id)}</td>
            <td>${formatValue(item.username)}</td>
            <td>${formatValue(item.email)}</td>
            <td>${formatValue(item.role)}</td>
            <td>${formatValue(item.client_source)}</td>
            <td>${formatDate(item.logged_in_at)}</td>
        </tr>
    `).join("");
}

async function loadLoginCollections() {
    refreshButton.disabled = true;
    setStatus("Loading stored login details...");

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/login-collections`);
        const data = await response.json().catch(() => []);

        if (!response.ok) {
            throw new Error(typeof data.detail === "string" ? data.detail : "Unable to load login details.");
        }

        renderRows(data);
        setStatus(`Loaded ${data.length} stored login record${data.length === 1 ? "" : "s"}.`, "success");
    } catch (error) {
        loginCollectionsBody.innerHTML = '<tr><td colspan="7">Unable to load stored login details right now.</td></tr>';
        setStatus(error.message || "Unable to load login details.", "error");
    } finally {
        refreshButton.disabled = false;
    }
}

refreshButton.addEventListener("click", loadLoginCollections);

renderBrowserSession();
loadLoginCollections();
