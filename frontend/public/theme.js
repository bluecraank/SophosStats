// Setzt das Farbschema vor dem ersten Rendern (kein Aufblitzen). Standard: dunkel.
(function () {
  var theme = "dark";
  try {
    theme = localStorage.getItem("theme") || "dark";
  } catch (e) {
    /* Speicher nicht verfügbar */
  }
  document.documentElement.classList.toggle("dark", theme === "dark");
})();
