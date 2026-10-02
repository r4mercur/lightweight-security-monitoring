// Resizable table columns for tables with a data-resize="<key>" attribute.
//
// Drag the right edge of a header cell, or focus that edge (Tab) and use the
// arrow keys. A double-click on an edge restores the automatic widths. Widths
// are remembered per table key in this browser (localStorage), so they survive
// reloads and the tables htmx swaps in (filters, overview refresh).
//
// Widths are set through the CSSOM (element.style.width), which the Content
// Security Policy allows; style attributes in the markup would not be.
(function () {
  "use strict";

  const MIN_WIDTH = 48;
  const KEY_STEP = 16;
  const STORAGE_PREFIX = "secmon.columns.";

  // Storage can be unavailable (private mode, disabled); resizing still works.
  function load(key) {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_PREFIX + key));
    } catch {
      return null;
    }
  }
  function save(key, widths) {
    try {
      localStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(widths));
    } catch {}
  }
  function forget(key) {
    try {
      localStorage.removeItem(STORAGE_PREFIX + key);
    } catch {}
  }

  function headers(table) {
    return table.tHead ? Array.from(table.tHead.rows[0].cells) : [];
  }

  function widthOf(th) {
    return parseFloat(th.style.width) || th.getBoundingClientRect().width;
  }

  // Sets explicit widths for all columns and switches the table to a fixed
  // layout, so a column keeps the width it is given instead of its content's.
  function apply(table, widths) {
    const ths = headers(table);
    if (widths.length !== ths.length || !widths.every(w => typeof w === "number" && w > 0)) {
      return false; // columns changed since the widths were stored
    }
    ths.forEach((th, i) => { th.style.width = widths[i] + "px"; });
    table.style.width = widths.reduce((sum, w) => sum + w, 0) + "px";
    table.classList.add("resized");
    return true;
  }

  // Before the first resize, takes over the widths the browser chose.
  function freeze(table) {
    if (!table.classList.contains("resized")) {
      apply(table, headers(table).map(th => th.getBoundingClientRect().width));
    }
  }

  function setWidth(table, th, width) {
    const old = widthOf(th);
    const w = Math.max(MIN_WIDTH, Math.round(width));
    th.style.width = w + "px";
    table.style.width = (parseFloat(table.style.width) + w - old) + "px";
  }

  function remember(table) {
    save(table.dataset.resize, headers(table).map(widthOf));
  }

  function reset(table) {
    headers(table).forEach(th => { th.style.width = ""; });
    table.style.width = "";
    table.classList.remove("resized");
    forget(table.dataset.resize);
  }

  function addHandle(table, th) {
    const handle = document.createElement("span");
    handle.className = "col-resize";
    handle.tabIndex = 0;
    handle.setAttribute("role", "separator");
    handle.setAttribute("aria-orientation", "vertical");
    handle.setAttribute("aria-label", "Column width: " + th.textContent.trim());
    handle.title = "Drag to resize · double-click to reset all columns";
    th.appendChild(handle);

    handle.addEventListener("pointerdown", e => {
      if (e.button !== 0) return;
      e.preventDefault();
      freeze(table);
      const startX = e.clientX;
      const startWidth = widthOf(th);
      handle.setPointerCapture(e.pointerId);
      table.classList.add("resizing");

      const move = ev => setWidth(table, th, startWidth + ev.clientX - startX);
      const end = () => {
        handle.removeEventListener("pointermove", move);
        handle.removeEventListener("pointerup", end);
        handle.removeEventListener("pointercancel", end);
        table.classList.remove("resizing");
        remember(table);
      };
      handle.addEventListener("pointermove", move);
      handle.addEventListener("pointerup", end);
      handle.addEventListener("pointercancel", end);
    });

    handle.addEventListener("dblclick", () => reset(table));

    handle.addEventListener("keydown", e => {
      const delta = { ArrowRight: KEY_STEP, ArrowLeft: -KEY_STEP }[e.key];
      if (!delta) return;
      e.preventDefault();
      freeze(table);
      setWidth(table, th, widthOf(th) + delta);
      remember(table);
    });
  }

  function init(table) {
    if (table.dataset.resizeReady) return;
    table.dataset.resizeReady = "true";
    const stored = load(table.dataset.resize);
    if (Array.isArray(stored)) apply(table, stored);
    headers(table).forEach(th => addHandle(table, th));
  }

  function scan(root) {
    if (root.matches && root.matches("table[data-resize]")) init(root);
    root.querySelectorAll("table[data-resize]").forEach(init);
  }

  document.addEventListener("DOMContentLoaded", () => scan(document));
  // htmx fires htmx:load for every piece of content it swaps in.
  document.addEventListener("htmx:load", e => scan(e.target));
})();
