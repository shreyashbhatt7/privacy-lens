// network/cname-detector.js
//
// A subdomain like data.thesite.com can look first-party while its DNS
// CNAME record actually points at a third-party tracking vendor's
// infrastructure — dodging third-party cookie blocking entirely.
// Chrome extensions have no raw DNS API, so we ask Cloudflare's
// DNS-over-HTTPS resolver what the CNAME chain actually is.
//
// This is the flakiest piece over conference wifi, so: short timeout,
// small in-memory cache so we don't re-resolve the same host every
// request, and a bundled-list fallback if DoH fails or is slow.

import { createTrackingEvent } from "../shared/events.js";
import { appendEvent } from "../lib/store.js";
import { isKnownTracker, isAllowlisted, getRegistrableDomain } from "./tracker-list.js";

const DOH_TIMEOUT_MS = 1500;
const cnameCache = new Map(); // hostname -> { chain: string[], ts: number }
const CACHE_TTL_MS = 10 * 60 * 1000;

async function resolveCnameChain(hostname) {
  const cached = cnameCache.get(hostname);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    console.log(`[PrivacyLens][cname] cache hit for ${hostname}:`, cached.chain);
    return cached.chain;
  }

  console.log(`[PrivacyLens][cname] attempting DoH lookup for ${hostname}`);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CNAME`,
      { headers: { Accept: "application/dns-json" }, signal: controller.signal }
    );
    clearTimeout(timer);
    if (!res.ok) {
      console.log(`[PrivacyLens][cname] DoH responded non-OK (${res.status}) for ${hostname}`);
      return null;
    }
    const data = await res.json();
    const chain = (data.Answer ?? [])
      .filter((a) => a.type === 5) // type 5 = CNAME
      .map((a) => a.data.replace(/\.$/, ""));
    console.log(`[PrivacyLens][cname] DoH resolved ${hostname} ->`, chain.length ? chain : "(no CNAME record)");
    cnameCache.set(hostname, { chain, ts: Date.now() });
    return chain;
  } catch (err) {
    clearTimeout(timer);
    console.log(`[PrivacyLens][cname] DoH failed/timed out for ${hostname}:`, err.name);
    return null; // DoH failed/timed out — caller falls back to bundled list
  }
}

/**
 * @param {Object} params
 * @param {string} params.requestHostname - hostname actually being requested (e.g. data.thesite.com)
 * @param {string} params.topSite         - site the user is browsing (e.g. thesite.com)
 * @param {number} params.tabId
 */
export async function inspectForCnameCloaking({ requestHostname, topSite, tabId }) {
  const requestRegDomain = getRegistrableDomain(requestHostname);
  const topRegDomain = getRegistrableDomain(topSite);

  // Only worth checking hosts that LOOK first-party (same registrable domain
  // as the site) — cloaking's whole trick is appearing first-party.
  if (requestRegDomain !== topRegDomain) return;
  if (await isAllowlisted(requestHostname)) {
    console.log(`[PrivacyLens][cname] ${requestHostname} is allowlisted, skipping`);
    return;
  }

  const chain = await resolveCnameChain(requestHostname);

  let cloakedTarget = null;
  let confidence = 0;
  let evidenceApi = "DNS-over-HTTPS (cloudflare-dns.com)";

  if (chain && chain.length > 0) {
    for (const cnameTarget of chain) {
      const cnameRegDomain = getRegistrableDomain(cnameTarget);
      if (cnameRegDomain !== topRegDomain && (await isKnownTracker(cnameTarget))) {
        cloakedTarget = cnameTarget;
        confidence = 0.9; // live DNS evidence is strong
        break;
      }
    }
  } else {
    // DoH unavailable — fall back to: does this subdomain's naming pattern
    // match known first-party-tracker-proxy conventions? Weak signal only.
    evidenceApi = "bundled tracker list (DoH unavailable)";
    if (await isKnownTracker(requestHostname)) {
      cloakedTarget = requestHostname;
      confidence = 0.35;
    }
  }

  if (!cloakedTarget) {
    console.log(`[PrivacyLens][cname] no cloaking detected for ${requestHostname}`);
    return;
  }

  const event = createTrackingEvent({
    tabId,
    site: topSite,
    category: "network",
    subtype: "cname-cloaking",
    source: { requestHostname },
    target: { domain: cloakedTarget },
    evidence: { api: evidenceApi, cnameChain: chain ?? [] },
    severity: confidence >= 0.7 ? "high" : "medium",
    confidence,
  });

  await appendEvent(event);
}
