import { cpSync } from "node:fs";

cpSync(new URL("../assets", import.meta.url), new URL("../dist/assets", import.meta.url), { recursive: true });
