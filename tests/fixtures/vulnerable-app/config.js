// Planted vulnerability (fixture): hardcoded secret (fake test credential).
// gitleaks flags this as a GitHub PAT (github-pat rule).
const GITHUB_TOKEN = "a3f5c9e1b7d2486094a1c8e5f2b6d0a3c7e9f1b4d6082a5c";

module.exports = { GITHUB_TOKEN };
