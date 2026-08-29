import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

export default [
  ...nextVitals,
  ...nextTs,
  {
    ignores: [
      ".next/**",
      "out/**",
      "build/**",
      "dist/**",
      "next-env.d.ts",
    ],
  },
  {
    rules: {
      "@typescript-eslint/no-explicit-any": "warn",
      "no-console": "warn",
      "react/no-danger": "error",
    },
  },
  {
    // Security-sensitive randomness must go through lib/random/cryptoRandom.ts
    files: [
      "lib/cipher/**/*.{ts,tsx}",
      "lib/security/**/*.{ts,tsx}",
      "lib/kdf/**/*.{ts,tsx}",
      "lib/protocols/**/*.{ts,tsx}",
      "lib/crypto/**/*.{ts,tsx}",
    ],
    ignores: ["**/*.test.ts", "**/*.test.tsx"],
    rules: {
      "no-restricted-properties": [
        "error",
        {
          object: "Math",
          property: "random",
          message:
            "Math.random() is not cryptographically secure. Use cryptoRandomBytes()/cryptoRandomInt() from lib/random/cryptoRandom.ts.",
        },
      ],
    },
  },
];

