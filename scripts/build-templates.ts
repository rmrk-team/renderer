import { readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { buildTemplate } from "./build-utils";

const REPO_ROOT = resolve(import.meta.dir, "..");
const TEMPLATES_DIR = join(REPO_ROOT, "src", "templates");

async function listTemplates() {
  const entries = await readdir(TEMPLATES_DIR);
  const templates: string[] = [];
  for (const entry of entries) {
    const fullPath = join(TEMPLATES_DIR, entry);
    const info = await stat(fullPath);
    if (info.isDirectory()) {
      templates.push(entry);
    }
  }
  return templates;
}

async function main() {
  const templates = await listTemplates();
  if (templates.length === 0) {
    console.warn("No templates found.");
    return;
  }
  for (const template of templates) {
    await buildTemplate(template);
    console.log(`Built template: ${template}`);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
