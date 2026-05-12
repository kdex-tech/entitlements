# @kdex-tech/entitlements

TypeScript implementation of KDex entitlements verification. See the Go package's `entitlements.go` for the canonical reference and full documentation of the pattern forms (long / medium / short / opaque) — this port preserves the same semantics.

## Install

```sh
npm install @kdex-tech/entitlements
```

## Usage

```ts
import { EntitlementsChecker } from "@kdex-tech/entitlements";

const ec = new EntitlementsChecker(
  ["public:read"],  // anonymous entitlements (granted to all callers)
  "bearer",          // default scheme
  false,             // grantReadyByDefault
);

const userEntitlements = {
  bearer: ["pages:read", "books:write"],
};

const requirements = [
  { bearer: ["pages:read"] },
];

ec.verifyEntitlements(userEntitlements, requirements); // true
```

For repeated checks against the same entitlements/requirements, pre-parse for performance:

```ts
const parsedEnt = ec.parseEntitlements(userEntitlements);
const parsedReq = ec.parseRequirements(requirements);
ec.verifyParsedEntitlements(parsedEnt, parsedReq);
```

## Build

```sh
make build   # tsc → dist/
make test    # vitest run
make lint    # eslint src
```
