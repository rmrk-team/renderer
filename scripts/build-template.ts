import { buildTemplate } from "./build-utils";

const templateName = process.argv[2];

buildTemplate(templateName)
  .then(() => {
    console.log(`Built template: ${templateName}`);
  })
  .catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
