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
const loginForm = document.getElementById("login-form");
const loginButton = document.getElementById("login-button");
const statusMessage = document.getElementById("status-message");
const passwordToggles = document.querySelectorAll(".toggle-password");

function setStatus(message, type = "") {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`.trim();
}

async function submitLogin(event) {
    event.preventDefault();

    const payload = Object.fromEntries(new FormData(loginForm).entries());

    loginButton.disabled = true;
    loginButton.textContent = "Logging in...";
    setStatus("Sending login request...");

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Client-App": "frontend-login",
            },
            body: JSON.stringify(payload),
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(typeof data.detail === "string" ? data.detail : "Login failed.");
        }

        window.authStorage.saveAuthSession(data);
        loginForm.reset();
        setStatus(data.message || "Login successful.", "success");
        window.setTimeout(() => {
            window.location.assign("/dashboard");
        }, 500);
    } catch (error) {
        setStatus(error.message || "Unable to log in right now.", "error");
    } finally {
        loginButton.disabled = false;
        loginButton.textContent = "Login Account";
    }
}

loginForm.addEventListener("submit", submitLogin);

passwordToggles.forEach((toggle) => {
    toggle.addEventListener("click", () => {
        const targetName = toggle.dataset.target;
        const input = loginForm.querySelector(`input[name="${targetName}"]`);
        if (!input) {
            return;
        }

        const shouldShow = input.type === "password";
        input.type = shouldShow ? "text" : "password";
        toggle.textContent = shouldShow ? "Hide" : "Show";
    });
});

const savedSession = window.authStorage.loadAuthSession();
if (savedSession) {
    window.location.replace("/dashboard");
}
