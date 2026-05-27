const dashboardTitle = document.getElementById("dashboard-title");
const dashboardUserId = document.getElementById("dashboard-user-id");
const dashboardUsername = document.getElementById("dashboard-username");
const dashboardEmail = document.getElementById("dashboard-email");
const dashboardRole = document.getElementById("dashboard-role");
const logoutButton = document.getElementById("logout-button");

function fillDashboard(session) {
    dashboardTitle.textContent = `Welcome, ${session.user.username}.`;
    dashboardUserId.textContent = session.user.id;
    dashboardUsername.textContent = session.user.username;
    dashboardEmail.textContent = session.user.email;
    dashboardRole.textContent = session.user.role;
}

const session = window.authStorage.loadAuthSession();

if (!session || !session.user) {
    window.location.replace("/login");
} else {
    fillDashboard(session);
}

logoutButton.addEventListener("click", () => {
    window.authStorage.clearAuthSession();
    window.location.replace("/login");
});
