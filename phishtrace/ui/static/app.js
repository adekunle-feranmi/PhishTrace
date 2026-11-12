/* PhishTrace console bootstrap (full UI added in the UI phase). */
(async function () {
  "use strict";
  const who = document.getElementById("who");
  try {
    const res = await fetch("/api/session", { headers: { Accept: "application/json" } });
    if (res.status === 401) { window.location.href = "/login"; return; }
    const data = await res.json();
    if (who) who.textContent = data.user ? data.user.username : "";
    window.PHISHTRACE = { csrf: data.csrf || "", user: data.user || null };
  } catch (err) {
    if (who) who.textContent = "offline";
  }
  const logout = document.getElementById("logout");
  if (logout) {
    logout.addEventListener("click", async () => {
      await fetch("/logout", { method: "POST", headers: { "X-CSRF-Token": (window.PHISHTRACE || {}).csrf || "" } });
      window.location.href = "/login";
    });
  }
})();
