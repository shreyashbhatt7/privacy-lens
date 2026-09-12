// background.js — MV3 service worker entry point.
//
// Kept intentionally thin: just boots the network interceptor. Person 2's
// fingerprint hooks and Person 3's correlation engine attach their own
// listeners/imports here too once ready — this file is where the whole
// pipeline gets wired together.

import { initInterceptor } from "./network/interceptor.js";

initInterceptor();

// Lets the extension icon open the side panel on click (Person 3's UI).
chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true }).catch(() => {});

console.log("[PrivacyLens] background worker started, network interceptor active");
