document.addEventListener("click", async (event) => {
  const toggle = event.target.closest("[data-toggle]");
  if (toggle) {
    const field = document.getElementById(toggle.dataset.toggle);
    field.type = field.type === "password" ? "text" : "password";
    toggle.textContent = field.type === "password" ? "Show" : "Hide";
  }
  const copy = event.target.closest("[data-copy]");
  if (copy) {
    const field = document.getElementById(copy.dataset.copy);
    try {
      await navigator.clipboard.writeText(field.value);
      copy.textContent = "Copied";
      setTimeout(() => { copy.textContent = "Copy"; }, 2000);
    } catch (_) {
      copy.textContent = "Select & copy";
      field.type = "text";
      field.select();
    }
  }
});
document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});
