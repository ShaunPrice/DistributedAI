// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const notice = document.getElementById("notice");
async function request(path, body) {
  const response = await fetch(
    `/platform/${path}`,
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
  );
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result;
}
async function refresh() {
  const data = await request("state");
  document.getElementById("signin").hidden = true;
  document.getElementById("console").hidden = false;
  const target = document.getElementById("accounts");
  target.replaceChildren();
  for (const account of data.accounts) {
    const section = document.createElement("section");
    const title = document.createElement("h3");
    title.textContent = account.account_id;
    const details = document.createElement("p");
    details.textContent = `${account.suspended ? "Suspended" : "Active"} · Created ${account.created_at} · ${account.principal_count} principals · ${account.scope_count} scopes`;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = account.suspended
      ? "Resume account"
      : "Suspend account";
    button.addEventListener("click", async () => {
      if (!window.confirm(`${button.textContent} ${account.account_id}?`))
        return;
      button.disabled = true;
      try {
        await request("accounts", {
          account_id: account.account_id,
          suspended: !account.suspended,
        });
        notice.textContent = "Account availability updated.";
        await refresh();
      } catch (error) {
        notice.textContent = error.message;
        button.disabled = false;
      }
    });
    section.append(title, details, button);
    if (data.billing_enabled) {
      const status = document.createElement("p");
      status.textContent = `Plan: ${account.plan} · Billing: ${account.billing_status}${account.needs_reconciliation ? " · Reconciliation required" : ""}`;
      const label = document.createElement("label");
      label.textContent = "Assign account plan ";
      const select = document.createElement("select");
      for (const plan of Object.keys(data.plans)) {
        const option = document.createElement("option");
        option.value = plan;
        option.textContent = plan;
        option.selected = plan === account.plan;
        select.append(option);
      }
      label.append(select);
      const save = document.createElement("button");
      save.type = "button";
      save.textContent = "Assign plan";
      save.addEventListener("click", async () => {
        if (
          !window.confirm(
            `Assign ${select.value} to account ${account.account_id}? This changes limits immediately; future payment events may update the plan.`,
          )
        )
          return;
        save.disabled = true;
        try {
          await request("accounts/plan", {
            account_id: account.account_id,
            plan: select.value,
          });
          notice.textContent =
            "Account plan assigned. Project access is unchanged.";
          await refresh();
        } catch (error) {
          notice.textContent = error.message;
          save.disabled = false;
        }
      });
      section.append(status, label, save);
    }
    target.append(section);
  }
  if (data.truncated)
    notice.textContent = "Only the first 1,000 accounts are shown.";
}
document.getElementById("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("credential");
  const token = input.value;
  input.value = "";
  try {
    await request("login", { token });
    notice.textContent = "";
    await refresh();
  } catch (error) {
    notice.textContent = error.message;
  }
});
document.getElementById("refresh").addEventListener("click", () =>
  refresh().catch((error) => {
    notice.textContent = error.message;
  }),
);
document.getElementById("logout").addEventListener("click", async () => {
  try {
    await request("logout", {});
    document.getElementById("accounts").replaceChildren();
    document.getElementById("console").hidden = true;
    document.getElementById("signin").hidden = false;
    notice.textContent = "Signed out.";
  } catch (error) {
    notice.textContent = error.message;
  }
});
request("login-options")
  .then((options) => {
    document.getElementById("login").hidden = !options.token;
    const link = document.getElementById("cloud-login");
    link.hidden = !options.oidc;
    link.textContent = `Sign in with ${options.provider}`;
  })
  .catch((error) => {
    notice.textContent = error.message;
  });
refresh().catch(() => {});
