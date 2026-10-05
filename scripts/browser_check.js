async page => {
  // Run against the reviewed benign example report only. No user profile or evidence.
  const target = page.url();
  if (!target.startsWith('http://127.0.0.1:8766/') || !target.endsWith('/report.html')) throw new Error('Open the reviewed benign example on the loopback test server first');
  const external = [], errors = [], dialogs = [], consoleErrors=[];
  page.on('request', request => { if (/^https?:/i.test(request.url())) external.push(request.url()); });
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (['error','warning'].includes(message.type())) consoleErrors.push(message.text()); });
  page.on('dialog', async dialog => { dialogs.push(dialog.type()); await dialog.dismiss(); });
  await page.context().setOffline(false);
  await page.goto(target);
  await page.context().setOffline(true);
  const before = await page.locator('.searchable:visible').count();
  await page.getByRole('searchbox', {name: 'Search evidence'}).fill('BINARY_WORKBENCH_BENIGN_FIXTURE');
  const after = await page.locator('.searchable:visible').count();
  if (!(after > 0 && after < before)) throw new Error('offline_search_failed');
  await page.getByRole('searchbox', {name: 'Search evidence'}).fill('no_such_marker_427f');
  if (await page.locator('.searchable:visible').count() !== 0) throw new Error('negative_search_failed');
  await page.getByRole('searchbox', {name: 'Search evidence'}).fill('');
  await page.getByRole('link', {name: 'string_fixture', exact: true}).click();
  if (!/#function-/.test(page.url())) throw new Error('function_navigation_failed');
  const evidenceLinks = page.locator('a[href^="#e-string:"]');
  if (!(await evidenceLinks.count())) throw new Error('reference_links_missing');
  await evidenceLinks.first().click();
  const href = await evidenceLinks.first().getAttribute('href');
  const targetExists = await page.evaluate(id => Boolean(document.getElementById(id)), href.slice(1));
  if (!targetExists) throw new Error('reference_target_missing');
  const injectedScripts = await page.locator('script').count();
  if (injectedScripts !== 1 || dialogs.length || errors.length || external.some(url=>!url.startsWith('http://127.0.0.1:8766/')) || consoleErrors.length) throw new Error('inert_offline_report_failed');
  await page.setViewportSize({width:1440,height:960});
  await page.getByRole('searchbox', {name:'Search evidence'}).focus();
  await page.keyboard.press('Control+Home');
  await page.screenshot({path:'examples/benign-pe64/report.png'});
  return {status:'PASS',before,after,external_requests:external.filter(url=>!url.startsWith('http://127.0.0.1:8766/')).length,page_errors:errors.length,
          dialogs:dialogs.length,scripts:injectedScripts,reference_target_exists:targetExists};
}
