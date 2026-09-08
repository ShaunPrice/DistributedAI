// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(() => {
  const prefix = location.pathname.startsWith("/platform") ? "/platform" : "/manage";
  const dialog = document.createElement("dialog");
  dialog.className = "help-dialog";
  dialog.setAttribute("aria-labelledby", "help-title");
  const close = document.createElement("button");
  close.className = "secondary";
  close.textContent = "Close help";
  close.addEventListener("click", () => dialog.close());
  const title = document.createElement("h2");
  title.id = "help-title";
  const topics = document.createElement("select");
  topics.setAttribute("aria-label", "Help topic");
  const body = document.createElement("div");
  const escalate = document.createElement("button");
  escalate.textContent = "Escalate issue to support";
  escalate.addEventListener("click", () => {
    dialog.close();
    if (prefix === "/manage" && typeof state !== "undefined" && state) {
      perform(() => window.DistributedSupport.escalate(topics.value));
    } else {
      dialog.showModal();
      body.replaceChildren();
      const message = document.createElement("p");
      message.textContent = "If you cannot sign in, contact your organisation administrator through your established support channel. For solution support configuration, use the platform administrator console. Never send your access token.";
      body.append(message);
      fetch(prefix + "/support-entry", {credentials: "same-origin"}).then((r) => r.ok ? r.json() : null).then((data) => {
        if (data?.route?.kind === "external") {
          const link = document.createElement("a");
          link.href = data.route.url;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.textContent = "Open solution support portal";
          body.append(link);
        }
      }).catch(() => {});
    }
  });
  async function load(page) {
    try {
      const response = await fetch(prefix + "/help?page=" + encodeURIComponent(page), {credentials: "same-origin"});
      if (!response.ok) throw new Error("Help is temporarily unavailable.");
      const data = await response.json();
      title.textContent = data.title;
      body.replaceChildren();
      data.paragraphs.forEach((text) => {
        const p = document.createElement("p");
        p.textContent = text;
        body.append(p);
      });
      topics.replaceChildren();
      data.topics.forEach((topic) => {
        const option = document.createElement("option");
        option.value = topic.page;
        option.textContent = topic.title;
        topics.append(option);
      });
      topics.value = data.page;
    } catch (error) {
      body.textContent = error.message;
    }
  }
  topics.addEventListener("change", () => load(topics.value));
  dialog.append(close, title, topics, body, escalate);
  document.body.append(dialog);
  document.querySelectorAll("[data-help-page]").forEach((button) => button.addEventListener("click", async () => {
    await load(button.dataset.helpPage);
    dialog.showModal();
    close.focus();
  }));
})();
