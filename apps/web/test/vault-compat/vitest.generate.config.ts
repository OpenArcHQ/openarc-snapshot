// P08-00: runs ONLY the golden fixture generator. The default `vitest run` never matches this file.
import path from "node:path";

import { defineConfig } from "vitest/config";

export default defineConfig({
  root: path.resolve(import.meta.dirname, "../.."),
  test: {
    include: ["test/vault-compat/generate-fixtures.ts"],
    fileParallelism: false,
  },
});
