// Planted vulnerability (fixture): hardcoded secret (fake test credential).
// Detected by gitleaks' generic-api-key rule. Intentionally NOT a real-provider
// token pattern, so it does not trip GitHub push protection on a public repo.
const API_KEY = "a3f5c9e1b7d2486094a1c8e5f2b6d0a3c7e9f1b4d6082a5c";

module.exports = { API_KEY };
