import {join} from 'node:path';
import {preparedBuild,run} from './build.mjs';
try {
 const {destination}=preparedBuild();
 // No downloaded checkout, dependency install, or fetched lifecycle scripts.
 run(process.execPath,[join(destination,'node_modules/wrangler/bin/wrangler.js'),'deploy','--keep-vars',...process.argv.slice(2)],destination);
} catch {console.error('Deployment refused or failed; check the local build.');process.exitCode=1;}
