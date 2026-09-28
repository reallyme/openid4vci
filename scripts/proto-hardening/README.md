# Generated Proto Hardening Core

`core.mjs` owns the reusable Buffa post-generation transformations for
sensitive `bytes`, optional `bytes`, `bytes` inside oneofs, generated views,
owned views, and generated Debug output.

Repository wrappers supply only absolute paths and an error prefix:

```js
import { hardenGeneratedProto } from "./proto-hardening/core.mjs";

hardenGeneratedProto({
  failurePrefix: "generated example proto hardening failed",
  protoPath,
  generatedPath,
  oneofPath,
  viewPath,
  viewOneofPath,
});
```

The source `.proto` is the sensitive-field policy: every message or oneof
`bytes` field discovered there is hardened. Wrappers must point to fresh Buffa
output and run exactly once after generation. Repository release checks should
inspect the shared core, wrapper configuration, generated output, and generated
security tests.

Sibling repositories should consume a pinned copy or pinned upstream revision
of `core.mjs`; they should not fork its transformation logic into a
repository-specific script.
