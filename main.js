/* ================================================================
   AI CYBERCRIME INVESTIGATION ASSISTANT
   Shared frontend behaviour                          (JAVASCRIPT)
================================================================ */

// Highlight active nav link based on current URL
document.addEventListener("DOMContentLoaded", () => {
  const path = window.location.pathname;
  document.querySelectorAll(".nav-links a").forEach(link => {
    if (link.getAttribute("href") === path) {
      link.classList.add("active");
    }
  });

  // (JAVASCRIPT) Mobile hamburger menu toggle
  const hamburgerBtn = document.getElementById("hamburgerBtn");
  const mobileNavPanel = document.getElementById("mobileNavPanel");
  if (hamburgerBtn && mobileNavPanel) {
    hamburgerBtn.addEventListener("click", () => {
      mobileNavPanel.classList.toggle("open");
    });
    // close menu after tapping a link
    mobileNavPanel.querySelectorAll("a").forEach(link => {
      link.addEventListener("click", () => mobileNavPanel.classList.remove("open"));
    });
  }

  // auto-dismiss alert banners after 4 seconds
  document.querySelectorAll(".alert").forEach(alertBox => {
    setTimeout(() => {
      alertBox.style.transition = "opacity 0.5s";
      alertBox.style.opacity = "0";
      setTimeout(() => alertBox.remove(), 500);
    }, 4000);
  });
});
