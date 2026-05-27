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
  ["public:read"],  // anonymous-only: applied when the caller's entitlements bag is empty
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

## Base entitlements (floor for every caller)

`anonymousEntitlements` (the constructor argument) is applied **only** to callers who pass an empty entitlements map. For grants that should apply to every caller — authenticated or anonymous — use the fluent `withBaseEntitlements` setter:

```ts
const ec = new EntitlementsChecker(
  ["public:read"],  // anonymous-only: only fires when caller's bag is empty
  "bearer",
  false,
).withBaseEntitlements(["heartbeat:read"]);  // floor: every caller gets this
```

Calling `withBaseEntitlements` again replaces the previously set list.

## Build

```sh
make build   # tsc → dist/
make test    # vitest run
make lint    # eslint src
```
