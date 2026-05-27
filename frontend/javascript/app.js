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
const signupForm = document.getElementById("signup-form");
const submitButton = document.getElementById("submit-button");
const statusMessage = document.getElementById("status-message");
const passwordToggles = document.querySelectorAll(".toggle-password");

function setStatus(message, type = "") {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`.trim();
}

function validateForm(payload) {
    if (!payload.username.trim()) {
        return "Username is required.";
    }

    if (!/^\d{10}$/.test(payload.phone_number)) {
        return "Phone number must be exactly 10 digits.";
    }

    if (payload.password !== payload.confirm_password) {
        return "Password and confirm password must match.";
    }

    return "";
}

async function submitSignup(event) {
    event.preventDefault();

    const payload = Object.fromEntries(new FormData(signupForm).entries());
    const validationMessage = validateForm(payload);

    if (validationMessage) {
        setStatus(validationMessage, "error");
        return;
    }

    submitButton.disabled = true;
    submitButton.textContent = "Creating account...";
    setStatus("Sending signup request...");

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/signup`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Client-App": "frontend-signup",
            },
            body: JSON.stringify(payload),
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(typeof data.detail === "string" ? data.detail : "Signup failed.");
        }

        window.authStorage.clearAuthSession();
        signupForm.reset();
        setStatus("Account created successfully. Please login to continue.", "success");
        window.setTimeout(() => {
            window.location.assign("/login");
        }, 700);
    } catch (error) {
        setStatus(error.message || "Unable to create account right now.", "error");
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Create account";
    }
}

signupForm.addEventListener("submit", submitSignup);

passwordToggles.forEach((toggle) => {
    toggle.addEventListener("click", () => {
        const targetName = toggle.dataset.target;
        const input = signupForm.querySelector(`input[name="${targetName}"]`);
        if (!input) {
            return;
        }

        const shouldShow = input.type === "password";
        input.type = shouldShow ? "text" : "password";
        toggle.textContent = shouldShow ? "Hide" : "Show";
    });
});
