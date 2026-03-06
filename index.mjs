import { generatePKCE } from "@openauthjs/openauth/pkce";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { open } from "./db.mjs";

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

// --- Logging ---

const LOG_PATH = join(homedir(), ".opencode", "data", "anthropic-pool.log");
function poolLog(msg) {
  const ts = new Date().toISOString();
  try {
    writeFileSync(LOG_PATH, `${ts} ${msg}\n`, { flag: "a" });
  } catch {}
}

// --- SQLite pool helpers ---

// Staleness TTLs (ms)
const STALE_5H = 3600000; // 1 hour
const STALE_7D = 43200000; // 12 hours
const STALE_OVERAGE = 1800000; // 30 min
const TRANSIENT_THRESHOLD = 10000;
const CLOCK_SKEW_BUFFER = 2000;
const FALLBACK_COOLDOWN = 30000;
const MAX_RETRY_AFTER = 60;
const THRESHOLD = 0.8;

function loadPool() {
  const db = open();
  const rows = db
    .prepare("SELECT * FROM account WHERE status = 'active'")
    .all();
  if (!rows.length) return null;
  const now = Date.now();
  return {
    accounts: rows.map((r) => ({
      id: r.id,
      label: r.label,
      refresh: r.refresh,
      access: r.access || "",
      expires: r.expires || 0,
      util5h: now - r.util5h_at < STALE_5H ? r.util5h : 0,
      util7d: now - r.util7d_at < STALE_7D ? r.util7d : 0,
      cooloffUntil: r.cooldown_until || 0,
      overage: now - r.overage_at < STALE_OVERAGE ? !!r.overage : false,
    })),
    config: { threshold: THRESHOLD },
  };
}

function saveUtil(account) {
  const db = open();
  const now = Date.now();
  db.prepare(
    `
    UPDATE account SET
      util5h = ?, util5h_at = ?,
      util7d = ?, util7d_at = ?,
      overage = ?, overage_at = ?
    WHERE id = ?
  `,
  ).run(
    account.util5h,
    now,
    account.util7d,
    now,
    account.overage ? 1 : 0,
    now,
    account.id,
  );
}

function saveRefresh(account) {
  const db = open();
  db.prepare(
    "UPDATE account SET refresh = ?, access = ?, expires = ? WHERE id = ?",
  ).run(account.refresh, account.access, account.expires, account.id);
}

function readRefresh(id) {
  const db = open();
  const row = db.prepare("SELECT refresh FROM account WHERE id = ?").get(id);
  return row?.refresh ?? null;
}

function markDead(id, reason) {
  const db = open();
  db.prepare("UPDATE account SET status = 'dead' WHERE id = ?").run(id);
  poolLog(`marked "${id}" as dead: ${reason}`);
}

function setCooldown(id, until) {
  const db = open();
  db.prepare("UPDATE account SET cooldown_until = ? WHERE id = ?").run(
    until,
    id,
  );
}

// --- Account selection ---

function pickNext(pool, current) {
  const now = Date.now();
  const threshold = pool.config.threshold;
  const currentUtil = Math.max(current.util5h, current.util7d);
  const available = pool.accounts.filter(
    (a) => a !== current && now >= a.cooloffUntil,
  );
  if (!available.length) return current;
  // Prefer healthy accounts (under threshold, no overage)
  const healthy = available.filter(
    (a) => Math.max(a.util5h, a.util7d) < threshold && !a.overage,
  );
  if (healthy.length) return healthy[0];
  // Prefer accounts with lower utilization than current
  const better = available.filter(
    (a) => Math.max(a.util5h, a.util7d) < currentUtil,
  );
  if (better.length) {
    better.sort(
      (a, b) => Math.max(a.util5h, a.util7d) - Math.max(b.util5h, b.util7d),
    );
    return better[0];
  }
  // All accounts are equally bad — pick the one with lowest util anyway
  available.sort(
    (a, b) => Math.max(a.util5h, a.util7d) - Math.max(b.util5h, b.util7d),
  );
  return available[0];
}

// --- Token refresh (reads latest from DB, optimistic recovery on failure) ---

async function refreshToken(account) {
  // Read latest token from DB (another process may have rotated it)
  const disk = readRefresh(account.id);
  if (disk && disk !== account.refresh) {
    poolLog(`re-read fresher token for "${account.label}" from db`);
    account.refresh = disk;
  }

  const response = await fetch("https://console.anthropic.com/v1/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "refresh_token",
      refresh_token: account.refresh,
      client_id: CLIENT_ID,
    }),
  });

  if (!response.ok) {
    // Optimistic recovery: re-read DB, if token changed another process refreshed
    const retry = readRefresh(account.id);
    if (retry && retry !== account.refresh) {
      poolLog(
        `optimistic recovery for "${account.label}": token changed in db`,
      );
      account.refresh = retry;
      const r2 = await fetch("https://console.anthropic.com/v1/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "refresh_token",
          refresh_token: account.refresh,
          client_id: CLIENT_ID,
        }),
      });
      if (r2.ok) {
        const json = await r2.json();
        account.refresh = json.refresh_token;
        account.access = json.access_token;
        account.expires = Date.now() + json.expires_in * 1000;
        saveRefresh(account);
        return true;
      }
    }
    // Truly dead if disk token matches what we tried
    const current = readRefresh(account.id);
    if (current === account.refresh) {
      markDead(account.id, "invalid_grant after optimistic retry");
    }
    poolLog(`refresh failed for "${account.label}"`);
    return false;
  }

  const json = await response.json();
  account.refresh = json.refresh_token;
  account.access = json.access_token;
  account.expires = Date.now() + json.expires_in * 1000;
  saveRefresh(account);
  return true;
}

// --- Utilization header parsing ---

function parseUtil(response, account) {
  const h5 = response.headers.get("anthropic-ratelimit-unified-5h-utilization");
  const h7 = response.headers.get("anthropic-ratelimit-unified-7d-utilization");
  const overage = response.headers.get(
    "anthropic-ratelimit-unified-overage-in-use",
  );
  if (h5 != null) account.util5h = parseFloat(h5);
  if (h7 != null) account.util7d = parseFloat(h7);
  if (overage != null) account.overage = overage === "true";
}

function parseCooldown(response, now = Date.now()) {
  const ms = parseInt(response.headers.get("retry-after-ms"));
  if (ms > 0) return now + ms;

  const val = parseFloat(response.headers.get("retry-after"));
  if (val > 0) return now + val * 1000;

  const reset = [
    "anthropic-ratelimit-requests-reset",
    "anthropic-ratelimit-tokens-reset",
    "anthropic-ratelimit-input-tokens-reset",
    "anthropic-ratelimit-output-tokens-reset",
  ].flatMap((header) => {
    const val = response.headers.get(header);
    if (val == null) return [];
    const ts = new Date(val).getTime();
    if (Number.isNaN(ts)) return [];
    if (ts <= now) return [now + CLOCK_SKEW_BUFFER];
    return [ts];
  });
  if (reset.length) return Math.min(...reset);

  return now + FALLBACK_COOLDOWN;
}

// --- OAuth flow ---

async function authorize(mode) {
  const pkce = await generatePKCE();
  const url = new URL(
    `https://${mode === "console" ? "console.anthropic.com" : "claude.ai"}/oauth/authorize`,
    import.meta.url,
  );
  url.searchParams.set("code", "true");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set(
    "redirect_uri",
    "https://console.anthropic.com/oauth/code/callback",
  );
  url.searchParams.set(
    "scope",
    "org:create_api_key user:profile user:inference",
  );
  url.searchParams.set("code_challenge", pkce.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", pkce.verifier);
  return { url: url.toString(), verifier: pkce.verifier };
}

async function exchange(code, verifier) {
  const splits = code.split("#");
  const result = await fetch("https://console.anthropic.com/v1/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code: splits[0],
      state: splits[1],
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      redirect_uri: "https://console.anthropic.com/oauth/code/callback",
      code_verifier: verifier,
    }),
  });
  if (!result.ok) return { type: "failed" };
  const json = await result.json();
  return {
    type: "success",
    refresh: json.refresh_token,
    access: json.access_token,
    expires: Date.now() + json.expires_in * 1000,
  };
}

// --- Request/response transforms ---

const TOOL_PREFIX = "mcp_";

function buildRequest(input, init, access) {
  const requestInit = init ?? {};
  const requestHeaders = new Headers();
  if (input instanceof Request) {
    input.headers.forEach((value, key) => {
      requestHeaders.set(key, value);
    });
  }
  if (requestInit.headers) {
    if (requestInit.headers instanceof Headers) {
      requestInit.headers.forEach((value, key) => {
        requestHeaders.set(key, value);
      });
    } else if (Array.isArray(requestInit.headers)) {
      for (const [key, value] of requestInit.headers) {
        if (typeof value !== "undefined") {
          requestHeaders.set(key, String(value));
        }
      }
    } else {
      for (const [key, value] of Object.entries(requestInit.headers)) {
        if (typeof value !== "undefined") {
          requestHeaders.set(key, String(value));
        }
      }
    }
  }

  const incomingBeta = requestHeaders.get("anthropic-beta") || "";
  const incomingBetasList = incomingBeta
    .split(",")
    .map((b) => b.trim())
    .filter(Boolean);
  const requiredBetas = ["oauth-2025-04-20", "interleaved-thinking-2025-05-14"];
  const mergedBetas = [
    ...new Set([...requiredBetas, ...incomingBetasList]),
  ].join(",");

  requestHeaders.set("authorization", `Bearer ${access}`);
  requestHeaders.set("anthropic-beta", mergedBetas);
  requestHeaders.set("user-agent", "claude-cli/2.1.2 (external, cli)");
  requestHeaders.delete("x-api-key");

  let body = requestInit.body;
  if (body && typeof body === "string") {
    try {
      const parsed = JSON.parse(body);
      if (parsed.system && Array.isArray(parsed.system)) {
        parsed.system = parsed.system.map((item) => {
          if (item.type === "text" && item.text) {
            return {
              ...item,
              text: item.text
                .replace(/OpenCode/g, "Claude Code")
                .replace(/(?<!\/)opencode/gi, "Claude"),
            };
          }
          return item;
        });
      }
      if (parsed.tools && Array.isArray(parsed.tools)) {
        parsed.tools = parsed.tools.map((tool) => ({
          ...tool,
          name: tool.name ? `${TOOL_PREFIX}${tool.name}` : tool.name,
        }));
      }
      if (parsed.messages && Array.isArray(parsed.messages)) {
        parsed.messages = parsed.messages.map((msg) => {
          if (msg.content && Array.isArray(msg.content)) {
            msg.content = msg.content.map((block) => {
              if (block.type === "tool_use" && block.name) {
                return { ...block, name: `${TOOL_PREFIX}${block.name}` };
              }
              return block;
            });
          }
          return msg;
        });
      }
      body = JSON.stringify(parsed);
    } catch (e) {}
  }

  let requestInput = input;
  let requestUrl = null;
  try {
    if (typeof input === "string" || input instanceof URL) {
      requestUrl = new URL(input.toString());
    } else if (input instanceof Request) {
      requestUrl = new URL(input.url);
    }
  } catch {
    requestUrl = null;
  }

  if (
    requestUrl &&
    requestUrl.pathname === "/v1/messages" &&
    !requestUrl.searchParams.has("beta")
  ) {
    requestUrl.searchParams.set("beta", "true");
    requestInput =
      input instanceof Request
        ? new Request(requestUrl.toString(), input)
        : requestUrl;
  }

  return { requestInput, body, requestHeaders };
}

function wrapStream(response) {
  if (response.body) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      async pull(controller) {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        let text = decoder.decode(value, { stream: true });
        text = text.replace(/"name"\s*:\s*"mcp_([^"]+)"/g, '"name": "$1"');
        controller.enqueue(encoder.encode(text));
      },
    });
    return new Response(stream, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  }
  return response;
}

// --- Plugin export ---

export async function AnthropicAuthPlugin({ client }) {
  return {
    "experimental.chat.system.transform": (input, output) => {
      const prefix =
        "You are Claude Code, Anthropic's official CLI for Claude.";
      if (input.model?.providerID === "anthropic") {
        output.system.unshift(prefix);
        if (output.system[1])
          output.system[1] = prefix + "\n\n" + output.system[1];
      }
    },

    auth: {
      provider: "anthropic",
      async loader(getAuth, provider) {
        poolLog("loader called");
        const auth = await getAuth();
        const pool = loadPool();

        if ((auth && auth.type === "oauth") || pool) {
          for (const model of Object.values(provider.models)) {
            model.cost = { input: 0, output: 0, cache: { read: 0, write: 0 } };
          }

          // Pool mode
          if (pool) {
            // Start with healthiest account, not arbitrary DB order
            pool.accounts.sort((a, b) => {
              if (a.overage !== b.overage) return a.overage ? 1 : -1;
              return (
                Math.max(a.util5h, a.util7d) - Math.max(b.util5h, b.util7d)
              );
            });
            let current = pool.accounts[0];
            poolLog(
              `pool mode: ${pool.accounts.length} accounts, starting with "${current.label}" (5h=${current.util5h.toFixed(2)} 7d=${current.util7d.toFixed(2)} overage=${current.overage})`,
            );

            return {
              apiKey: "",
              async fetch(input, init) {
                // Ensure valid token
                if (!current.access || current.expires < Date.now()) {
                  const ok = await refreshToken(current);
                  if (!ok) {
                    const prev = current;
                    setCooldown(current.id, Date.now() + FALLBACK_COOLDOWN);
                    current.cooloffUntil = Date.now() + FALLBACK_COOLDOWN;
                    current = pickNext(pool, current);
                    poolLog(
                      `refresh failed, switching from "${prev.label}" to "${current.label}"`,
                    );
                    const ok2 = await refreshToken(current);
                    if (!ok2) throw new Error("All accounts failed to refresh");
                  }
                }

                const req = buildRequest(input, init, current.access);
                const response = await fetch(req.requestInput, {
                  ...(init ?? {}),
                  body: req.body,
                  headers: req.requestHeaders,
                });

                parseUtil(response, current);
                saveUtil(current);

                // 401/403: refresh + retry
                if (response.status === 401 || response.status === 403) {
                  const ok = await refreshToken(current);
                  if (ok) {
                    const retry = buildRequest(input, init, current.access);
                    const r2 = await fetch(retry.requestInput, {
                      ...(init ?? {}),
                      body: retry.body,
                      headers: retry.requestHeaders,
                    });
                    parseUtil(r2, current);
                    saveUtil(current);
                    return wrapStream(r2);
                  }
                  // Refresh failed — try every other account before giving up
                  const until = parseCooldown(response);
                  setCooldown(current.id, until);
                  current.cooloffUntil = until;
                  const tried401 = new Set([current.id]);
                  let last401 = response;
                  while (tried401.size < pool.accounts.length) {
                    const prev = current;
                    current = pickNext(pool, current);
                    if (current === prev || tried401.has(current.id)) break;
                    tried401.add(current.id);
                    poolLog(
                      `401/403 trying "${current.label}" after "${prev.label}" failed`,
                    );
                    const ok2 = await refreshToken(current);
                    if (!ok2) continue;
                    const retry = buildRequest(input, init, current.access);
                    const r2 = await fetch(retry.requestInput, {
                      ...(init ?? {}),
                      body: retry.body,
                      headers: retry.requestHeaders,
                    });
                    parseUtil(r2, current);
                    saveUtil(current);
                    if (r2.status !== 401 && r2.status !== 403)
                      return wrapStream(r2);
                    last401 = r2;
                    const until = parseCooldown(r2);
                    setCooldown(current.id, until);
                    current.cooloffUntil = until;
                  }
                  return wrapStream(last401);
                }

                // 429: transient retry on same account first, then sustained rotation
                if (response.status === 429) {
                  const retryAfterMs =
                    parseFloat(response.headers.get("retry-after") || "0") *
                    1000;
                  const transient =
                    retryAfterMs > 0 && retryAfterMs <= TRANSIENT_THRESHOLD;
                  let latestResp;
                  if (transient) {
                    await new Promise((r) => setTimeout(r, retryAfterMs));
                    const sameRetry = buildRequest(input, init, current.access);
                    const sameResp = await fetch(sameRetry.requestInput, {
                      ...(init ?? {}),
                      body: sameRetry.body,
                      headers: sameRetry.requestHeaders,
                    });
                    if (sameResp.status !== 429) {
                      parseUtil(sameResp, current);
                      saveUtil(current);
                      return wrapStream(sameResp);
                    }
                    latestResp = sameResp;
                  } else {
                    latestResp = response;
                  }

                  const until = parseCooldown(latestResp);
                  setCooldown(current.id, until);
                  current.cooloffUntil = until;
                  const tried = new Set([current.id]);
                  let last429 = latestResp;
                  while (tried.size < pool.accounts.length) {
                    const prev = current;
                    current = pickNext(pool, current);
                    if (current === prev || tried.has(current.id)) break;
                    tried.add(current.id);
                    poolLog(
                      `429 trying "${current.label}" after "${prev.label}" rate limited`,
                    );
                    if (!current.access || current.expires < Date.now()) {
                      const ok = await refreshToken(current);
                      if (!ok) continue;
                    }
                    const retry = buildRequest(input, init, current.access);
                    const r2 = await fetch(retry.requestInput, {
                      ...(init ?? {}),
                      body: retry.body,
                      headers: retry.requestHeaders,
                    });
                    parseUtil(r2, current);
                    saveUtil(current);
                    if (r2.status !== 429) return wrapStream(r2);
                    const u = parseCooldown(r2);
                    setCooldown(current.id, u);
                    current.cooloffUntil = u;
                    last429 = r2;
                  }

                  const now = Date.now();
                  const times = pool.accounts
                    .map((a) => a.cooloffUntil)
                    .filter((t) => t > now);
                  const earliest = times.length
                    ? Math.min(...times)
                    : now + FALLBACK_COOLDOWN;
                  const secs = Math.max(
                    1,
                    Math.min(
                      Math.ceil((earliest - now) / 1000),
                      MAX_RETRY_AFTER,
                    ),
                  );
                  const hdrs = new Headers(last429.headers);
                  hdrs.set("retry-after", String(secs));
                  return new Response(last429.body, {
                    status: 429,
                    statusText: last429.statusText,
                    headers: hdrs,
                  });
                }

                // Proactive switch: only if there's a strictly healthier account
                // (not in overage, under threshold, and not in cooldown)
                // Don't switch away from a working account to one that might be worse
                if (
                  current.overage ||
                  Math.max(current.util5h, current.util7d) >
                    pool.config.threshold
                ) {
                  const candidate = pickNext(pool, current);
                  if (
                    candidate !== current &&
                    !candidate.overage &&
                    Math.max(candidate.util5h, candidate.util7d) <
                      pool.config.threshold
                  ) {
                    poolLog(
                      `proactive switch from "${current.label}" to "${candidate.label}" (5h=${current.util5h.toFixed(2)} 7d=${current.util7d.toFixed(2)} overage=${current.overage})`,
                    );
                    current = candidate;
                  }
                }

                return wrapStream(response);
              },
            };
          }

          // Single-account mode (no pool DB)
          return {
            apiKey: "",
            async fetch(input, init) {
              const auth = await getAuth();
              if (auth.type !== "oauth") return fetch(input, init);
              if (!auth.access || auth.expires < Date.now()) {
                const response = await fetch(
                  "https://console.anthropic.com/v1/oauth/token",
                  {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      grant_type: "refresh_token",
                      refresh_token: auth.refresh,
                      client_id: CLIENT_ID,
                    }),
                  },
                );
                if (!response.ok)
                  throw new Error(`Token refresh failed: ${response.status}`);
                const json = await response.json();
                await client.auth.set({
                  path: { id: "anthropic" },
                  body: {
                    type: "oauth",
                    refresh: json.refresh_token,
                    access: json.access_token,
                    expires: Date.now() + json.expires_in * 1000,
                  },
                });
                auth.access = json.access_token;
              }
              const req = buildRequest(input, init, auth.access);
              const response = await fetch(req.requestInput, {
                ...(init ?? {}),
                body: req.body,
                headers: req.requestHeaders,
              });
              if (response.status === 401 || response.status === 403) {
                const cur = await getAuth();
                if (cur.type !== "oauth") return wrapStream(response);
                const token = await fetch(
                  "https://console.anthropic.com/v1/oauth/token",
                  {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      grant_type: "refresh_token",
                      refresh_token: cur.refresh,
                      client_id: CLIENT_ID,
                    }),
                  },
                );
                if (!token.ok) return wrapStream(response);
                const json = await token.json();
                await client.auth.set({
                  path: { id: "anthropic" },
                  body: {
                    type: "oauth",
                    refresh: json.refresh_token,
                    access: json.access_token,
                    expires: Date.now() + json.expires_in * 1000,
                  },
                });
                const retry = buildRequest(input, init, json.access_token);
                const r2 = await fetch(retry.requestInput, {
                  ...(init ?? {}),
                  body: retry.body,
                  headers: retry.requestHeaders,
                });
                return wrapStream(r2);
              }
              return wrapStream(response);
            },
          };
        }

        return {};
      },
      methods: [
        {
          label: "Claude Pro/Max",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("max");
            return {
              url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => exchange(code, verifier),
            };
          },
        },
        {
          label: "Create an API Key",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("console");
            return {
              url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, verifier);
                if (credentials.type === "failed") return credentials;
                const result = await fetch(
                  `https://api.anthropic.com/api/oauth/claude_cli/create_api_key`,
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                      authorization: `Bearer ${credentials.access}`,
                    },
                  },
                ).then((r) => r.json());
                return { type: "success", key: result.raw_key };
              },
            };
          },
        },
        {
          provider: "anthropic",
          label: "Manually enter API Key",
          type: "api",
        },
      ],
    },
  };
}
