// Explicit setup metadata only. No inference, credentials, package execution or retries.
import { readdir, readFile, writeFile } from 'node:fs/promises';
const canonical = value => value.toLowerCase().replace(/[-_.]+/g, '-');
const wheels = (await readdir('.tools/wheels')).filter(x => x.endsWith('.whl'));
let failed = 0;
for (let start = 0; start < wheels.length; start += 4) {
  const results = await Promise.allSettled(wheels.slice(start, start + 4).map(async file => {
    const [name, version] = file.split('-');
    const target = `.tools/pypi/${name}-${version}.json`;
    try {
      const cached = JSON.parse(await readFile(target, 'utf8'));
      if (canonical(cached.info.name) === canonical(name) && cached.info.version === version) return name;
    } catch {}
    const response = await fetch(`https://pypi.org/pypi/${name}/${version}/json`, {signal: AbortSignal.timeout(30000)});
    if (!response.ok) throw new Error(name);
    const data = await response.json();
    if (canonical(data.info.name) !== canonical(name) || data.info.version !== version) throw new Error(name);
    await writeFile(target, JSON.stringify(data));
    return name;
  }));
  for (const result of results) {
    if (result.status === 'fulfilled') console.log(`${result.value}: official metadata available`);
    else { failed++; console.log('metadata request failed'); }
  }
}
process.exitCode = failed ? 1 : 0;
