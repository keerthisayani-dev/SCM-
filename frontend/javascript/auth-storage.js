const AUTH_STORAGE_KEY = "scmxpertlite.auth";

function saveAuthSession(authResponse) {
    if (!authResponse || !authResponse.access_token || !authResponse.user) {
        return;
    }

    const session = {
        accessToken: authResponse.access_token,
        tokenType: authResponse.token_type || "bearer",
        user: {
            id: authResponse.user.id,
            username: authResponse.user.username,
            email: authResponse.user.email,
            role: authResponse.user.role,
        },
        savedAt: new Date().toISOString(),
    };

    window.localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
}

function loadAuthSession() {
    const rawSession = window.localStorage.getItem(AUTH_STORAGE_KEY);
    if (!rawSession) {
        return null;
    }

    try {
        return JSON.parse(rawSession);
    } catch {
        window.localStorage.removeItem(AUTH_STORAGE_KEY);
        return null;
    }
}

function clearAuthSession() {
    window.localStorage.removeItem(AUTH_STORAGE_KEY);
}

window.authStorage = {
    clearAuthSession,
    loadAuthSession,
    saveAuthSession,
};
