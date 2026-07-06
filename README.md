# ❖ Prism Labs // Local Env Guard

`local-env-guard` is an elite, zero-trust local secret scanner designed to intercept, classify, and quarantine exposed API keys, credentials, and high-entropy tokens before they escape to the cloud. 

By executing entirely within your local terminal environment, it eliminates third-party API dependencies and data-leak risks, ensuring your development secrets remain completely private.

---

## 🚀 Key Architectural Highlights

* **Shannon Entropy Engine (Threshold > 4.5):** Goes beyond rigid regex pattern matching. It uses local mathematical frequency analysis to measure the randomness of strings, catching custom, un-flagged cryptographic keys while bypassing standard source code.
* **Zero-Trust File Sandboxing:** Implements rigorous repository jailing. The engine resolves absolute paths and drops any process attempting directory traversal attacks or external breakouts.
* **CWE-59 Symlink Protection:** Utilizes explicit `lstat()` inspection to detect and bypass symbolic links instantly, preventing loops and unauthorized system-file reads.
* **Heap Exhaustion Circuit Breaker:** Protects your machine's resources. Files larger than 5MB bypass string memory allocation and stream gracefully or skip to avoid blocking the Node.js event loop.
* **Intelligent Noise Filtering:** Features built-in structural exclusions for minified files and asset layers (`.css`, `.scss`, `.min.js`) to guarantee a near-zero false-positive rate.

---

## 📊 Streamlined Terminal Interface

When a leak is found, the tool prints a beautifully structured, monochrome-purple dashboard sorting findings into localized impact tiers:

┌──────────────────────────────────────────────────────────────────────────┐
│ ❖ Prism Labs // Local Env Guard                                         │
├──────────────────────────────────────────────────────────────────────────┤
│ Scanned 42 files and folders                                             │
│ Status: 2 findings                                                       │
├──────────────────────────────────────────────────────────────────────────┤
│ 🚨 CRITICAL PROVIDER KEYS                                                │
│ config/production.json:14 • Stripe                                       │
├──────────────────────────────────────────────────────────────────────────┤
│ ⚠️ HIGH-ENTROPY WARNINGS                                                 │
│ src/utils/auth.ts:8 • Entropy 4.82                                       │
└──────────────────────────────────────────────────────────────────────────┘

---

## 🛠️ Installation & Setup

Ensure you have [Node.js](https://nodejs.org/) installed locally.

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/tweetharis-netizen/local-env-guard.git](https://github.com/tweetharis-netizen/local-env-guard.git)
   cd local-env-guard
