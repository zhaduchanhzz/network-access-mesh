// Maps the Workers-only module `cloudflare:email` to the fake of the tests and of the local server (fake-email.mjs). Import
// this module first, then the Worker with a dynamic import(): static imports are linked before any module runs.
import { registerHooks } from "node:module";

const fake = new URL("./fake-email.mjs", import.meta.url).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "cloudflare:email") {
      return { url: fake, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});
