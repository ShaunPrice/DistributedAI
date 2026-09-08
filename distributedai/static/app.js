// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const $ = (id) => document.getElementById(id);
let state = null,
  people = [],
  grants = [],
  selectedCode = "";
function node(tag, text, cls) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (cls) el.className = cls;
  return el;
}
function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").className = "notice" + (error ? " error" : "");
  $("notice").hidden = false;
}
async function request(path, body) {
  const options = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch("/manage/" + path, options);
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) showLogin();
    throw new Error(data.error || "Request could not be completed");
  }
  return data;
}
const action = (op, args = {}) => request("api/" + op, args);
function showLogin() {
  state = null;
  $("workspace").hidden = true;
  $("login-panel").hidden = false;
  $("logout").hidden = true;
  $("identity").textContent = "Not signed in";
  $("organisation-name").textContent = "Connect your organisation";
  $("issued-token").textContent = "";
  $("manual-key").value = "";
  $("credential-panel").hidden = true;
  document.querySelectorAll("[data-admin]").forEach((el) => (el.hidden = true));
}
function options(id, entries, key, label) {
  const select = $(id),
    previous = select.value;
  select.replaceChildren();
  entries.forEach((item) => {
    const option = node("option", label(item));
    option.value = item[key];
    select.append(option);
  });
  if (entries.some((item) => item[key] === previous)) select.value = previous;
}
async function refresh() {
  state = await request("state");
  $("workspace").hidden = false;
  $("login-panel").hidden = true;
  $("logout").hidden = false;
  $("identity").textContent = state.principal.name;
  const root = state.scopes.find((s) => s.kind === "organisation");
  $("organisation-name").textContent = root ? root.name : "Assigned projects";
  document.querySelectorAll("[data-admin]").forEach((el) => {
    if (el.id !== "create-panel") el.hidden = !state.principal.is_org_admin;
  });
  const scopes = state.scopes;
  options(
    "parent-select",
    scopes.filter((s) => s.kind !== "project"),
    "scope_id",
    (s) => s.name + " · " + s.kind,
  );
  ["scope-select", "review-scope", "audit-scope"].forEach((id) =>
    options(id, scopes, "scope_id", (s) => s.name + " · " + s.kind),
  );
  renderProjects();
  if (state.principal.is_org_admin) {
    const result = await Promise.all([
      action("principal_list"),
      action("grant_list"),
    ]);
    people = result[0].principals;
    grants = result[1].grants;
    renderPeople();
  }
}
function renderProjects() {
  const list = $("project-list");
  list.replaceChildren();
  const scopes = state.scopes.filter((s) => s.kind !== "organisation");
  $("project-count").textContent = scopes.length + " visible";
  if (!scopes.length) {
    list.append(
      node(
        "p",
        state.principal.is_org_admin
          ? "Create your first project, then assign collaborators to it."
          : "No projects assigned yet. Ask your administrator to grant you project access.",
        "empty",
      ),
    );
    return;
  }
  scopes.forEach((scope) => {
    const row = node("button", undefined, "project-row");
    row.type = "button";
    row.append(
      node("span", scope.kind === "project" ? "↗" : "⊞", "project-icon"),
    );
    const title = node("span", scope.name);
    const parent = state.scopes.find((s) => s.scope_id === scope.parent_id);
    title.append(
      node(
        "small",
        scope.kind + " · " + (parent ? parent.name : "Assigned workspace"),
      ),
    );
    row.append(title);
    if (scope.project_code)
      row.append(node("span", scope.project_code, "project-code"));
    else row.append(node("span", "Department", "badge"));
    row.append(node("span", "→"));
    row.addEventListener("click", () => detail(scope));
    list.append(row);
  });
}
function detail(scope) {
  $("project-detail").hidden = false;
  $("detail-title").textContent = scope.name;
  selectedCode = scope.project_code || "";
  $("detail-code").textContent = selectedCode || "Department workspace";
  $("copy-code").hidden = !selectedCode;
  $("project-detail").scrollIntoView({ block: "nearest" });
}
function renderPeople() {
  options(
    "person-select",
    people.filter((p) => p.active),
    "principal_id",
    (p) => p.name,
  );
  const body = $("people-list");
  body.replaceChildren();
  people.forEach((person) => {
    const row = node("tr");
    row.append(
      node("td", person.name),
      node("td", person.active ? "Active" : "Revoked"),
    );
    const cell = node("td");
    if (person.active && person.principal_id !== state.principal.id) {
      const button = node("button", "Revoke identity", "danger");
      button.addEventListener("click", () =>
        perform(async () => {
          if (
            !confirm(
              "Revoke " +
                person.name +
                "? Their browser sessions and AI connections will stop working.",
            )
          )
            return;
          await action("principal_revoke", {
            principal_id: person.principal_id,
          });
          await refresh();
          notice("Identity revoked.");
        }),
      );
      cell.append(button);
    }
    row.append(cell);
    body.append(row);
  });
  const access = $("grants-list");
  access.replaceChildren();
  grants.forEach((grant) => {
    const row = node("tr"),
      person = people.find((p) => p.principal_id === grant.principal_id),
      scope = state.scopes.find((s) => s.scope_id === grant.scope_id);
    row.append(
      node("td", person ? person.name : grant.principal_id),
      node("td", scope ? scope.name : grant.scope_id),
      node("td", grant.role),
    );
    const cell = node("td"),
      button = node("button", "Remove assignment", "danger");
    button.addEventListener("click", () =>
      perform(async () => {
        if (
          !confirm(
            "Remove this access assignment? Inherited access may still apply.",
          )
        )
          return;
        await action("grant_revoke", {
          principal_id: grant.principal_id,
          scope_id: grant.scope_id,
        });
        await refresh();
        notice("Access assignment removed.");
      }),
    );
    cell.append(button);
    row.append(cell);
    access.append(row);
  });
}
async function renderReviews() {
  const target = $("review-list");
  target.replaceChildren();
  const scope = $("review-scope").value;
  if (!scope) return;
  const result = await action("proposal_list", { scope_id: scope, limit: 100 });
  const items = result.proposals || [];
  if (!items.length)
    target.append(
      node("p", "No proposals waiting for review in this workspace.", "empty"),
    );
  items.forEach((item) => {
    const card = node("article", undefined, "review-card");
    card.append(
      node("h2", item.key),
      node(
        "span",
        item.quarantined ? "Quarantined · promotion blocked" : item.status,
        "badge",
      ),
      node("pre", item.content),
      node(
        "p",
        "Source: " +
          (item.source || "Not supplied") +
          " · " +
          (item.epistemic_kind || "observation"),
      ),
    );
    if (item.findings?.length)
      card.append(node("p", "Screening findings: " + item.findings.join(", ")));
    if (item.status === "pending" && item.proposer_id !== state.principal.id) {
      [true, false].forEach((accept) => {
        const button = node(
          "button",
          accept ? "Accept memory" : "Reject proposal",
          accept ? "" : "secondary",
        );
        button.disabled = accept && item.quarantined;
        button.addEventListener("click", () =>
          perform(async () => {
            const outcome = await action("memory_review", {
              proposal_id: item.proposal_id,
              accept,
            });
            notice("Proposal " + outcome.status + ".");
            await renderReviews();
          }),
        );
        card.append(button);
      });
    }
    target.append(card);
  });
}
async function renderAudit() {
  const target = $("audit-list");
  target.replaceChildren();
  const scope = $("audit-scope").value;
  if (!scope) return;
  const result = await action("audit_list", { scope_id: scope, limit: 100 });
  if (!result.entries.length)
    target.append(node("p", "No audit events in this scope yet.", "empty"));
  result.entries.forEach((entry) => {
    const card = node("article", undefined, "review-card");
    card.append(
      node("h2", entry.action),
      node("pre", JSON.stringify(entry, null, 2)),
    );
    target.append(card);
  });
}
async function switchView(name) {
  if (!state) return;
  if (
    ["people", "audit", "keys"].includes(name) &&
    !state.principal.is_org_admin
  )
    return;
  document
    .querySelectorAll(".view")
    .forEach((view) => (view.hidden = view.id !== name + "-view"));
  document
    .querySelectorAll("[data-view]")
    .forEach((button) =>
      button.classList.toggle("selected", button.dataset.view === name),
    );
  $("view-label").textContent = {
    projects: "PROJECTS",
    people: "PEOPLE & ACCESS",
    reviews: "MEMORY REVIEWS",
    audit: "AUDIT TRAIL",
    keys: "ENCRYPTION KEYS",
    billing: "CONNECTIONS & PLAN",
  }[name];
  if (name === "reviews") await renderReviews();
  if (name === "audit") await renderAudit();
  if (name === "keys") await renderKeys();
  if (name === "billing") await renderBilling();
}
async function perform(fn) {
  try {
    await fn();
  } catch (error) {
    notice(error.message, true);
  }
}
function submit(id, fn) {
  $(id).addEventListener("submit", (event) => {
    event.preventDefault();
    const form = event.currentTarget,
      button = form.querySelector("button[type=submit],button:not([type])");
    if (button) button.disabled = true;
    perform(() => fn(form)).finally(() => {
      if (button) button.disabled = false;
    });
  });
}
submit("login-form", async () => {
  const token = $("access-token").value;
  try {
    await request("login", { token });
  } finally {
    $("access-token").value = "";
  }
  await refresh();
  await switchView("projects");
  $("notice").hidden = true;
});
submit("create-form", async (form) => {
  const result = await action(
    "scope_create",
    Object.fromEntries(new FormData(form)),
  );
  form.reset();
  $("create-panel").hidden = true;
  await refresh();
  detail(result);
  notice("Workspace created. Assign access in People & access.");
});
submit("person-form", async (form) => {
  const result = await action(
    "principal_create",
    Object.fromEntries(new FormData(form)),
  );
  $("issued-token").textContent = result.issued_token;
  $("credential-panel").hidden = false;
  form.reset();
  await refresh();
  notice("Identity created. Save their token and assign project access.");
});
submit("grant-form", async (form) => {
  await action("grant", Object.fromEntries(new FormData(form)));
  await refresh();
  notice("Access assignment saved.");
});
submit("resolve-form", async () => {
  const result = await action("project_resolve", {
    project_code: $("project-code").value.trim(),
  });
  detail(result.scope || result);
  notice("Project opened.");
});
$("show-create").addEventListener("click", () => {
  $("create-panel").hidden = !$("create-panel").hidden;
  if (!$("create-panel").hidden) $("create-form").elements.name.focus();
});
$("copy-code").addEventListener("click", () =>
  perform(async () => {
    await navigator.clipboard.writeText(selectedCode);
    notice("Project code copied.");
  }),
);
$("dismiss-token").addEventListener("click", () => {
  $("issued-token").textContent = "";
  $("manual-key").value = "";
  $("credential-panel").hidden = true;
});
$("logout").addEventListener("click", () =>
  perform(async () => {
    await request("logout", {});
    showLogin();
    notice("Signed out.");
  }),
);
document
  .querySelectorAll("[data-view]")
  .forEach((button) =>
    button.addEventListener("click", () =>
      perform(() => switchView(button.dataset.view)),
    ),
  );
$("review-scope").addEventListener("change", () => perform(renderReviews));
$("audit-scope").addEventListener("change", () => perform(renderAudit));
showLogin();
refresh().catch(() => {});

request("login-options")
  .then((options) => {
    $("login-form").hidden = !options.token;
    $("cloud-login").hidden = !options.oidc;
    $("cloud-hint").hidden = !options.oidc;
    $("cloud-login").textContent = "Sign in with " + options.provider;
  })
  .catch(() => notice("Sign-in configuration could not be loaded."));

async function renderKeys() {
  const keys = await request("keys");
  $("key-status").textContent =
    keys.algorithm + " · Active version " + keys.active_version;
  options(
    "key-provider",
    keys.providers.map((name) => ({ name })),
    "name",
    (item) => item.name,
  );
  $("key-versions").replaceChildren(
    ...keys.versions.map((version) =>
      node("p", "Version " + version.version + " · " + version.provider),
    ),
  );
}
submit("key-form", async () => {
  const input = $("manual-key");
  const payload = { provider: $("key-provider").value };
  if (input.value) payload.manual_key = input.value;
  input.value = "";
  try {
    await request("keys/rotate", payload);
  } finally {
    delete payload.manual_key;
  }
  await renderKeys();
  notice(
    "Encryption key rotated. Previous key versions remain available for existing content.",
  );
});

async function renderBilling() {
  const [instances, connections] = await Promise.all([
    action("instance_list"),
    action("connection_list"),
  ]);
  options(
    "connection-instance",
    instances.instances.filter((item) => item.active),
    "instance_id",
    (item) => item.name,
  );
  options(
    "connection-owner",
    state.principal.is_org_admin
      ? people.filter((item) => item.active)
      : [{ principal_id: state.principal.id, name: state.principal.name }],
    "principal_id",
    (item) => item.name,
  );
  const list = $("connection-list");
  list.replaceChildren();
  connections.connections.forEach((connection) => {
    const row = node("div", undefined, "form-panel");
    row.append(
      node("strong", connection.connection_id),
      node(
        "p",
        "Instance " +
          connection.instance_id +
          " · " +
          (connection.active ? "Active" : "Revoked"),
      ),
    );
    if (connection.active) {
      const revoke = node("button", "Revoke connection", "secondary");
      revoke.addEventListener("click", () =>
        perform(async () => {
          await action("connection_revoke", {
            connection_id: connection.connection_id,
          });
          await renderBilling();
        }),
      );
      row.append(revoke);
    }
    list.append(row);
  });
  if (state.principal.is_org_admin) {
    const billing = await action("billing_status");
    const maximum = billing.limits.max_connections ?? "unlimited";
    $("billing-summary").textContent = billing.billing_enabled
      ? billing.plan +
        " · " +
        billing.usage.connections +
        " / " +
        maximum +
        " connections · " +
        (billing.usage.storage_bytes / 1048576).toFixed(2) +
        " MiB stored"
      : "Self-hosted · Billing disabled · Unmetered connections";
    try {
      const available = await request("billing/options");
      const providers = Object.entries(available.providers || {}).map(
        ([name, flags]) => ({ name, ...flags }),
      );
      paymentOptions = { ...available, providers };
      options("payment-provider", providers, "name", (item) => item.name);
      updatePaymentPlans();
      $("payment-description").textContent = providers.length
        ? "Checkout takes place with the payment provider. Project access remains separately assigned."
        : "No payment provider is configured for this deployment.";
      $("checkout-button").disabled = !providers.some((p) => p.checkout);
      $("payment-portal").disabled = !providers.some((p) => p.portal);
    } catch {
      $("checkout-button").disabled = true;
      $("payment-portal").disabled = true;
    }
  } else
    $("billing-summary").textContent =
      "Your connections use the projects assigned to you.";
}
let paymentOptions = { providers: [], prices: [] };
function updatePaymentPlans() {
  options(
    "payment-plan",
    (paymentOptions.prices || []).filter(
      (item) => item.provider === $("payment-provider").value,
    ),
    "plan",
    (item) => item.plan,
  );
  const selected = (paymentOptions.providers || []).find(
    (item) => item.name === $("payment-provider").value,
  );
  $("checkout-button").disabled = !selected?.checkout;
  $("payment-portal").disabled = !selected?.portal;
}
$("payment-provider").addEventListener("change", updatePaymentPlans);
submit("instance-form", async (form) => {
  await action("instance_create", Object.fromEntries(new FormData(form)));
  form.reset();
  await renderBilling();
});
submit("connection-form", async () => {
  const result = await action("connection_issue", {
    instance_id: $("connection-instance").value,
    owner_principal_id: $("connection-owner").value,
  });
  $("issued-token").textContent = result.credential;
  $("credential-panel").hidden = false;
  await renderBilling();
  notice(
    "Connection credential issued. Copy it now; it cannot be retrieved later.",
  );
});
function openPayment(result) {
  const url = new URL(result.url);
  if (url.protocol !== "https:")
    throw new Error("Payment provider returned an invalid URL");
  window.location.assign(url.href);
}
submit("payment-form", async () =>
  openPayment(
    await request("billing/checkout", {
      provider: $("payment-provider").value,
      plan: $("payment-plan").value,
    }),
  ),
);
$("payment-portal").addEventListener("click", () =>
  perform(async () =>
    openPayment(
      await request("billing/portal", {
        provider: $("payment-provider").value,
      }),
    ),
  ),
);
