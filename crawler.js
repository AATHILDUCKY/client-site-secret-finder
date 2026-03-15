(function () {
  "use strict";

  const data = window.SECRET_FINDER_DATA || {
    patterns: [],
    whitelistPatterns: [],
    contextWhitelist: [],
    disclosurePaths: []
  };

  const state = {
    compiledPatterns: [],
    patternMap: new Map(),
    findings: [],
    visibleFindings: [],
    lastResult: null,
    scanning: false
  };

  const dom = {
    patternCountHeader: byId("patternCountHeader"),
    domainList: byId("domainList"),
    crawlDepth: byId("crawlDepth"),
    crawlMaxURLs: byId("crawlMaxURLs"),
    crawlMaxNew: byId("crawlMaxNew"),
    domainConcurrency: byId("domainConcurrency"),
    crawlConcurrency: byId("crawlConcurrency"),
    fetchConcurrency: byId("fetchConcurrency"),
    maxQueue: byId("maxQueue"),
    includeSubdomains: byId("includeSubdomains"),
    onlyLikelyFiles: byId("onlyLikelyFiles"),
    includePassiveSources: byId("includePassiveSources"),
    jsEndpointMining: byId("jsEndpointMining"),
    ignoreQueryParams: byId("ignoreQueryParams"),
    includeRegex: byId("includeRegex"),
    excludeRegex: byId("excludeRegex"),
    fetchTimeout: byId("fetchTimeout"),
    maxBodyMB: byId("maxBodyMB"),
    falsePositiveFilter: byId("falsePositiveFilter"),
    contextFilter: byId("contextFilter"),
    fastMode: byId("fastMode"),
    deepAnalysis: byId("deepAnalysis"),
    entropyFilter: byId("entropyFilter"),
    contextLines: byId("contextLines"),
    lineLimit: byId("lineLimit"),
    entropyMin: byId("entropyMin"),
    scanBtn: byId("scanBtn"),
    clearBtn: byId("clearBtn"),
    sampleBtn: byId("sampleBtn"),
    statusText: byId("statusText"),
    progressText: byId("progressText"),
    progressBar: byId("progressBar"),
    runLog: byId("runLog"),
    summaryCards: byId("summaryCards"),
    findingsMeta: byId("findingsMeta"),
    severityFilter: byId("severityFilter"),
    searchFilter: byId("searchFilter"),
    resultsBody: byId("resultsBody"),
    contextPanel: byId("contextPanel"),
    contextTitle: byId("contextTitle"),
    contextContent: byId("contextContent"),
    exportJSON: byId("exportJSON"),
    exportCSV: byId("exportCSV")
  };

  const htmlLinkRegex = /(?:href|src)\s*=\s*["']([^"']+)["']/gi;
  const htmlFormActionRegex = /action\s*=\s*["']([^"']+)["']/gi;
  const absoluteURLRegex = /https?:\/\/[^\s"'<>]+/g;
  const sourceMapRegex = /sourceMappingURL=([^\s]+)/gm;
  const quotedPathRegex = /["'](\/[^"'?#\s]{1,200}(?:\?[^"'\s]*)?)["']/g;
  const jsCallURLRegex = /(?:fetch|axios\.(?:get|post|put|patch|delete|request)|open|sendBeacon)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
  const jsImportRegex = /\b(?:import|require)\s*(?:\(|from\s*)["'`]([^"'`]+)["'`]/gi;
  const endpointLiteralRegex = /["'`](\/(?:api|v[0-9]+|graphql|auth|admin|internal)[^"'`\s]{0,240})["'`]/gi;
  const sitemapLocRegex = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  const functionCallRegex = /([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(/g;
  const suspiciousContextRegex = /(secret|token|passwd|password|authorization|bearer|private[_-]?key|credential|oauth|apikey|api[_-]?key)/i;

  init();

  function init() {
    compilePatterns();
    state.patternMap = new Map(data.patterns.map((p) => [p.name, p]));

    dom.scanBtn.addEventListener("click", runCrawlScan);
    dom.clearBtn.addEventListener("click", clearAll);
    dom.sampleBtn.addEventListener("click", loadSampleDomains);
    dom.severityFilter.addEventListener("change", applyViewFilters);
    dom.searchFilter.addEventListener("input", applyViewFilters);
    dom.exportJSON.addEventListener("click", exportJSON);
    dom.exportCSV.addEventListener("click", exportCSV);

    renderSummary(null);
    renderFindings([]);
    setStatus("Idle", 0);
    appendLog(`Ready. Loaded ${state.compiledPatterns.length}/${data.patterns.length} patterns.`);
  }

  function compilePatterns() {
    const compiled = [];
    let invalid = 0;

    for (const p of data.patterns) {
      try {
        compiled.push({ ...p, regexObj: new RegExp(p.regex, p.flags || "g") });
      } catch (err) {
        invalid += 1;
      }
    }

    state.compiledPatterns = compiled;
    dom.patternCountHeader.textContent = `${compiled.length} loaded`;

    if (invalid > 0) {
      appendLog(`Skipped ${invalid} unsupported pattern(s).`);
    }
  }

  async function runCrawlScan() {
    if (state.scanning) {
      return;
    }

    state.scanning = true;
    setBusy(true);
    setStatus("Preparing crawl scan...", 1);
    dom.runLog.textContent = "";

    const startedAt = performance.now();

    try {
      const options = readOptions();
      const domains = parseDomainList(dom.domainList.value);
      if (!domains.length) {
        throw new Error("add at least one domain name or URL");
      }

      appendLog(`Starting crawl scan for ${domains.length} domain(s).`);

      const allSources = [];
      const domainReports = [];
      let processedDomains = 0;

      await runConcurrent(domains, options.domainConcurrency, async (domainURL) => {
        appendLog(`[${domainURL}] crawling...`);
        const crawlResult = await crawlDomain(domainURL, options);
        appendLog(`[${domainURL}] discovered ${crawlResult.urls.length} URLs.`);

        const fetched = await fetchScanTargets(crawlResult.urls, options, options.fetchConcurrency, domainURL);
        let sources = fetched;

        const extra = discoverAdditionalTargetsFromFetched(domainURL, fetched, options.crawl.maxNew, options);
        if (extra.length) {
          appendLog(`[${domainURL}] expanded +${extra.length} URLs from fetched content.`);
          const expandedSources = await fetchScanTargets(extra, options, options.fetchConcurrency, domainURL);
          sources = sources.concat(expandedSources);
        }

        allSources.push(...sources);
        domainReports.push({
          domain: domainURL,
          discoveredURLs: crawlResult.urls.length + extra.length,
          fetchedSources: sources.length,
          crawlStats: crawlResult.stats
        });

        processedDomains += 1;
        const pct = Math.min(50, Math.floor((processedDomains / domains.length) * 50));
        setStatus(`Crawled ${processedDomains}/${domains.length} domain(s)`, pct);
      });

      const scanSources = dedupeSources(allSources)
        .map((s) => ({ ...s, content: prepareContentForScan(s.source, s.contentType, s.content, options) }))
        .filter((s) => s.content.trim().length > 0);

      if (!scanSources.length) {
        const result = {
          totalDomains: domains.length,
          totalFiles: 0,
          discoveredURLs: domainReports.reduce((sum, d) => sum + d.discoveredURLs, 0),
          totalMatches: 0,
          findings: [],
          scanDurationMs: Math.round(performance.now() - startedAt),
          patternsUsed: state.compiledPatterns.length,
          falsePositives: 0,
          domainReports
        };
        state.findings = [];
        state.lastResult = result;
        renderSummary(result);
        renderFindings([]);
        setStatus("No scanable sources", 100);
        return;
      }

      const totalLines = scanSources.reduce((sum, s) => sum + countLines(s.content), 0);
      let scannedLines = 0;
      const findings = [];

      appendLog(`Scanning ${scanSources.length} source(s) from crawled domains...`);

      for (let i = 0; i < scanSources.length; i += 1) {
        const sourceObj = scanSources[i];
        setStatus(`Scanning ${sourceObj.domain}`, 50 + Math.floor((i / scanSources.length) * 50));

        const sourceFindings = await scanContent(sourceObj, options, () => {
          scannedLines += 1;
          const scanPct = totalLines > 0 ? Math.floor((scannedLines / totalLines) * 50) : 50;
          setStatus(`Scanning ${sourceObj.domain}`, Math.min(100, 50 + scanPct));
        });
        findings.push(...sourceFindings);
      }

      const beforeFilter = findings.length;
      let filtered = findings;

      if (options.filters.falsePositive) {
        filtered = filterFalsePositives(filtered);
      }
      if (options.filters.contextWhitelist) {
        filtered = filterContextWhitelist(filtered);
      }
      if (options.filters.entropy) {
        filtered = filterWeakEntropyMatches(filtered, options.entropyMin);
      }

      filtered = filtered
        .map((finding) => ({ ...finding, riskScore: computeRiskScore(finding) }))
        .sort((a, b) => b.riskScore - a.riskScore);

      const result = {
        totalDomains: domains.length,
        totalFiles: scanSources.length,
        discoveredURLs: domainReports.reduce((sum, d) => sum + d.discoveredURLs, 0),
        totalMatches: filtered.length,
        findings: filtered,
        scanDurationMs: Math.round(performance.now() - startedAt),
        patternsUsed: state.compiledPatterns.length,
        falsePositives: beforeFilter - filtered.length,
        domainReports
      };

      state.findings = filtered;
      state.lastResult = result;
      renderSummary(result);
      applyViewFilters();
      setStatus("Crawl scan complete", 100);
      appendLog(`Done. Domains ${domains.length}, findings ${filtered.length}, filtered ${result.falsePositives}.`);
    } catch (err) {
      appendLog(`Error: ${err.message || String(err)}`);
      setStatus("Failed", 100);
    } finally {
      state.scanning = false;
      setBusy(false);
    }
  }

  function readOptions() {
    const timeoutSec = clampNumber(Number(dom.fetchTimeout.value), 3, 120, 20);
    const maxBodyMB = clampNumber(Number(dom.maxBodyMB.value), 1, 25, 5);

    return {
      timeoutSec,
      maxBodyBytes: Math.floor(maxBodyMB * 1024 * 1024),
      domainConcurrency: clampNumber(Number(dom.domainConcurrency.value), 1, 8, 4),
      fetchConcurrency: clampNumber(Number(dom.fetchConcurrency.value), 1, 16, 12),
      lineLimit: clampNumber(Number(dom.lineLimit.value), 300, 30000, 5000),
      contextLines: clampNumber(Number(dom.contextLines.value), 0, 5, 1),
      fastMode: dom.fastMode.checked,
      deepAnalysis: dom.deepAnalysis.checked,
      entropyMin: clampNumber(Number(dom.entropyMin.value), 1, 6, 3.2),
      filters: {
        falsePositive: dom.falsePositiveFilter.checked,
        contextWhitelist: dom.contextFilter.checked,
        entropy: dom.entropyFilter.checked
      },
      crawl: {
        depth: clampNumber(Number(dom.crawlDepth.value), 1, 12, 4),
        maxURLs: clampNumber(Number(dom.crawlMaxURLs.value), 10, 5000, 600),
        maxNew: clampNumber(Number(dom.crawlMaxNew.value), 0, 3000, 250),
        concurrency: clampNumber(Number(dom.crawlConcurrency.value), 1, 12, 8),
        maxQueue: clampNumber(Number(dom.maxQueue.value), 100, 50000, 12000),
        includeSubdomains: dom.includeSubdomains.checked,
        onlyLikelyFiles: dom.onlyLikelyFiles.checked,
        includePassiveSources: dom.includePassiveSources.checked,
        jsEndpointMining: dom.jsEndpointMining.checked,
        ignoreQueryParams: dom.ignoreQueryParams.checked,
        includeRegex: compileOptionalRegex(dom.includeRegex.value),
        excludeRegex: compileOptionalRegex(dom.excludeRegex.value)
      }
    };
  }

  function parseDomainList(raw) {
    const lines = String(raw || "")
      .split(/\r?\n/)
      .map((v) => v.trim())
      .filter((v) => !v.startsWith("#"))
      .filter(Boolean);

    const out = [];
    const seen = new Set();

    for (const line of lines) {
      try {
        const normalized = normalizeBaseURL(line);
        if (!seen.has(normalized)) {
          seen.add(normalized);
          out.push(normalized);
        }
      } catch (err) {
        appendLog(`Invalid domain skipped: ${line}`);
      }
    }

    return out;
  }

  function compileOptionalRegex(raw) {
    const value = String(raw || "").trim();
    if (!value) {
      return null;
    }

    let pattern = value;
    let flags = "i";
    const slashForm = value.match(/^\/(.+)\/([a-z]*)$/i);
    if (slashForm) {
      pattern = slashForm[1];
      flags = slashForm[2] || "i";
    }
    flags = flags.replaceAll("g", "").replaceAll("y", "");

    try {
      return new RegExp(pattern, flags);
    } catch (err) {
      throw new Error(`invalid regex: ${value}`);
    }
  }

  async function crawlDomain(baseURL, options) {
    const root = new URL(baseURL);
    const rootHost = root.hostname;

    const discoveredMap = new Map();
    const visitedSet = new Set();
    const queuedSet = new Set();
    const queue = [];

    const stats = {
      host: rootHost,
      visited: 0,
      fetched: 0,
      queued: 0,
      queuePeak: 0,
      skippedExternal: 0,
      skippedFilter: 0,
      skippedQueueLimit: 0,
      fetchErrors: 0,
      disclosureQueued: 0,
      passiveQueued: 0
    };

    function registerDiscovered(urlValue) {
      const scopeKey = buildURLScopeKey(urlValue, options.crawl.ignoreQueryParams);
      if (!discoveredMap.has(scopeKey) && discoveredMap.size < options.crawl.maxURLs) {
        discoveredMap.set(scopeKey, urlValue);
      }
    }

    function enqueue(urlValue, depth, reason) {
      if (depth > options.crawl.depth) {
        return;
      }
      if (queue.length >= options.crawl.maxQueue) {
        stats.skippedQueueLimit += 1;
        return;
      }

      const scopeKey = buildURLScopeKey(urlValue, options.crawl.ignoreQueryParams);
      if (queuedSet.has(scopeKey) || visitedSet.has(scopeKey)) {
        return;
      }

      queuedSet.add(scopeKey);
      registerDiscovered(urlValue);

      queue.push({
        url: urlValue,
        depth,
        key: scopeKey,
        priority: scoreCrawlTarget(urlValue, depth)
      });

      stats.queued += 1;
      stats.queuePeak = Math.max(stats.queuePeak, queue.length);
      if (reason === "disclosure") {
        stats.disclosureQueued += 1;
      } else if (reason === "passive") {
        stats.passiveQueued += 1;
      }
    }

    enqueue(baseURL, 0, "root");

    if (options.crawl.includePassiveSources) {
      for (const seed of buildPassiveSeedURLs(baseURL)) {
        if (!isInDomainScope(seed, rootHost, options.crawl.includeSubdomains)) {
          continue;
        }
        if (!passesCrawlFilters(seed, options.crawl)) {
          continue;
        }
        enqueue(seed, 0, "passive");
      }
    }

    for (const probe of buildDisclosureURLs(baseURL)) {
      if (!isInDomainScope(probe, rootHost, options.crawl.includeSubdomains)) {
        continue;
      }
      if (!passesCrawlFilters(probe, options.crawl)) {
        continue;
      }
      enqueue(probe, 0, "disclosure");
    }

    while (queue.length > 0 && discoveredMap.size < options.crawl.maxURLs) {
      queue.sort((a, b) => {
        if (a.depth !== b.depth) {
          return a.depth - b.depth;
        }
        return b.priority - a.priority;
      });

      const batch = queue.splice(0, options.crawl.concurrency);
      await runConcurrent(batch, options.crawl.concurrency, async (current) => {
        if (visitedSet.has(current.key)) {
          return;
        }
        visitedSet.add(current.key);
        queuedSet.delete(current.key);
        stats.visited += 1;

        if (current.depth > options.crawl.depth) {
          return;
        }

        try {
          const { content } = await fetchURLContent(current.url, options.timeoutSec, options.maxBodyBytes);
          stats.fetched += 1;

          let extracted = extractURLsFromContent(current.url, content, options.crawl);
          if (options.crawl.includePassiveSources) {
            if (isRobotsURL(current.url)) {
              extracted = extracted.concat(extractURLsFromRobots(current.url, content));
            }
            if (isSitemapURL(current.url)) {
              extracted = extracted.concat(extractURLsFromSitemap(current.url, content));
            }
          }

          const nextDepth = current.depth + 1;
          for (const found of uniqueStrings(extracted)) {
            if (!isInDomainScope(found, rootHost, options.crawl.includeSubdomains)) {
              stats.skippedExternal += 1;
              continue;
            }
            if (!passesCrawlFilters(found, options.crawl)) {
              stats.skippedFilter += 1;
              continue;
            }

            registerDiscovered(found);

            if (nextDepth > options.crawl.depth) {
              continue;
            }

            const crawlable = looksLikePage(found) || isLikelyScanTarget(found, "");
            if (options.crawl.onlyLikelyFiles && !crawlable) {
              stats.skippedFilter += 1;
              continue;
            }

            enqueue(found, nextDepth, "crawl");
          }
        } catch (err) {
          stats.fetchErrors += 1;
          appendLog(`Crawl miss: ${current.url} -> ${err.message || String(err)}`);
        }
      });
    }

    return {
      urls: prioritizeCrawlTargets(Array.from(discoveredMap.values()), options.crawl.onlyLikelyFiles).slice(0, options.crawl.maxURLs),
      stats
    };
  }

  function discoverAdditionalTargetsFromFetched(baseURL, fetchedSources, maxNew, options) {
    if (maxNew <= 0) {
      return [];
    }

    let rootHost = "";
    try {
      rootHost = new URL(baseURL).hostname;
    } catch (err) {
      return [];
    }

    const seen = new Set(fetchedSources.map((s) => buildURLScopeKey(s.source, options.crawl.ignoreQueryParams)));
    const out = [];

    for (const source of fetchedSources) {
      const extracted = extractURLsFromContent(source.source, source.content, options.crawl);
      for (const urlValue of extracted) {
        const dedupeKey = buildURLScopeKey(urlValue, options.crawl.ignoreQueryParams);
        if (!isInDomainScope(urlValue, rootHost, options.crawl.includeSubdomains)) {
          continue;
        }
        if (!passesCrawlFilters(urlValue, options.crawl)) {
          continue;
        }
        if (options.crawl.onlyLikelyFiles && !isLikelyScanTarget(urlValue, "") && !looksLikePage(urlValue)) {
          continue;
        }
        if (seen.has(dedupeKey)) {
          continue;
        }

        seen.add(dedupeKey);
        out.push(urlValue);

        if (looksLikeJavaScript(urlValue, "")) {
          const mapCandidate = `${urlValue}.map`;
          const mapKey = buildURLScopeKey(mapCandidate, options.crawl.ignoreQueryParams);
          if (!seen.has(mapKey)) {
            seen.add(mapKey);
            out.push(mapCandidate);
          }
        }

        if (out.length >= maxNew) {
          return out.slice(0, maxNew);
        }
      }
    }

    return prioritizeCrawlTargets(out, options.crawl.onlyLikelyFiles).slice(0, maxNew);
  }

  async function fetchScanTargets(targetURLs, options, concurrency, domain) {
    const out = [];

    await runConcurrent(targetURLs, concurrency, async (targetURL) => {
      try {
        const { content, contentType } = await fetchURLContent(targetURL, options.timeoutSec, options.maxBodyBytes);
        if (!shouldScanResponse(targetURL, contentType)) {
          return;
        }
        out.push({
          domain,
          source: targetURL,
          contentType,
          content
        });
      } catch (err) {
        appendLog(`Fetch skipped: ${targetURL} -> ${err.message || String(err)}`);
      }
    });

    return out.sort((a, b) => a.source.localeCompare(b.source));
  }

  async function scanContent(sourceObj, options, progressTick) {
    const findings = [];
    const lines = sourceObj.content.split("\n");

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx += 1) {
      let scanLine = lines[lineIdx];
      if (scanLine.length > options.lineLimit) {
        scanLine = scanLine.slice(0, options.lineLimit);
      }

      const variants = buildLineVariants(scanLine, options.deepAnalysis);
      const emitted = new Set();

      for (const variant of variants) {
        for (const p of state.compiledPatterns) {
          const regex = p.regexObj;
          regex.lastIndex = 0;
          let match;

          while ((match = regex.exec(variant.value)) !== null) {
            const matchedText = match[0] || "";
            if (matchedText.length >= 3) {
              const bestColumn = findMatchColumn(scanLine, matchedText, match.index);
              const key = `${lineIdx}:${p.name}:${bestColumn}:${matchedText.slice(0, 48)}`;

              if (!emitted.has(key)) {
                emitted.add(key);
                findings.push({
                  domain: sourceObj.domain,
                  source: sourceObj.source,
                  lineNumber: lineIdx + 1,
                  column: bestColumn + 1,
                  patternName: p.name,
                  matchedText,
                  context: getContext(lines, lineIdx + 1, options.contextLines),
                  severity: defaultString(p.severity, "MEDIUM"),
                  confidence: defaultString(p.confidence, "MEDIUM"),
                  category: defaultString(p.category, "Secrets Exposure"),
                  cwe: defaultString(p.cwe, "N/A"),
                  description: defaultString(p.description, p.name),
                  function: detectFunctionBehind(scanLine, bestColumn),
                  lineVariant: variant.kind,
                  entropy: calculateShannonEntropy(matchedText)
                });
              }
            }

            if (regex.lastIndex === match.index) {
              regex.lastIndex += 1;
            }
          }
        }
      }

      progressTick();

      if ((lineIdx + 1) % 80 === 0) {
        await sleep(0);
      }
    }

    return findings;
  }

  function filterFalsePositives(findings) {
    const filtered = [];
    const seen = new Set();

    for (const finding of findings) {
      const key = `${finding.domain}:${finding.source}:${finding.patternName}:${finding.lineNumber}:${finding.column}:${finding.matchedText.slice(0, 20)}`;
      if (seen.has(key)) {
        continue;
      }

      const pattern = state.patternMap.get(finding.patternName) || {};
      if (isLikelyFalsePositive(finding, pattern)) {
        continue;
      }

      seen.add(key);
      filtered.push(finding);
    }

    return filtered;
  }

  function filterContextWhitelist(findings) {
    const terms = (data.contextWhitelist || []).map((v) => String(v).toLowerCase());

    return findings.filter((finding) => {
      const lower = String(finding.context || "").toLowerCase();
      for (const term of terms) {
        if (lower.includes(term)) {
          return false;
        }
      }
      return true;
    });
  }

  function filterWeakEntropyMatches(findings, entropyMin) {
    return findings.filter((finding) => {
      const pattern = state.patternMap.get(finding.patternName) || {};
      const strongConfidence = String(pattern.confidence || finding.confidence || "").toUpperCase() === "HIGH";
      const hasSensitiveHint = suspiciousContextRegex.test(String(finding.context || "")) || suspiciousContextRegex.test(String(finding.patternName || ""));

      if (strongConfidence || hasSensitiveHint) {
        return true;
      }
      return Number(finding.entropy || 0) >= entropyMin;
    });
  }

  function isLikelyFalsePositive(finding, pattern) {
    const value = String(finding.matchedText || "");
    const lower = value.toLowerCase();

    for (const term of data.whitelistPatterns || []) {
      if (lower.includes(String(term).toLowerCase())) {
        return true;
      }
    }

    if (pattern.minLength && value.length < pattern.minLength) {
      return true;
    }
    if (pattern.maxLength && value.length > pattern.maxLength) {
      return true;
    }
    if (finding.lineVariant && finding.lineVariant !== "raw" && value.length < 6) {
      return true;
    }

    try {
      const hash = CryptoJS.SHA256(value).toString();
      if (hash.includes("aaaaa")) {
        return true;
      }
    } catch (err) {
      // ignore
    }

    let repeated = 0;
    for (let i = 1; i < value.length; i += 1) {
      if (value[i] === value[i - 1]) {
        repeated += 1;
        if (repeated > value.length / 3) {
          return true;
        }
      } else {
        repeated = 0;
      }
    }

    return false;
  }

  function computeRiskScore(finding) {
    const severity = String(finding.severity || "").toUpperCase();
    const confidence = String(finding.confidence || "").toUpperCase();
    const entropy = Number(finding.entropy || 0);

    let score = 35;
    if (severity === "CRITICAL") {
      score = 88;
    } else if (severity === "HIGH") {
      score = 72;
    } else if (severity === "MEDIUM") {
      score = 56;
    }

    if (confidence === "HIGH") {
      score += 8;
    } else if (confidence === "MEDIUM") {
      score += 4;
    }

    score += Math.min(12, Math.round(entropy * 2));

    if (suspiciousContextRegex.test(String(finding.context || "")) || suspiciousContextRegex.test(String(finding.patternName || ""))) {
      score += 8;
    }
    if (finding.lineVariant && finding.lineVariant !== "raw") {
      score += 4;
    }
    if (String(finding.cwe || "").toUpperCase() !== "N/A") {
      score += 2;
    }

    return Math.max(0, Math.min(100, score));
  }

  function renderSummary(result) {
    if (!result) {
      dom.summaryCards.innerHTML = "";
      return;
    }

    const queuePeakMax = Math.max(0, ...result.domainReports.map((r) => Number(r.crawlStats?.queuePeak || 0)));
    const cards = [
      ["Domains", result.totalDomains],
      ["Discovered URLs", result.discoveredURLs],
      ["Scanned Sources", result.totalFiles],
      ["Findings", result.totalMatches],
      ["Queue Peak", queuePeakMax],
      ["Patterns", result.patternsUsed],
      ["Duration", formatDuration(result.scanDurationMs)]
    ];

    dom.summaryCards.innerHTML = cards
      .map(([label, value]) => `
        <article class="rounded-xl border border-slate-800 bg-slate-900/70 p-4 shadow-soft">
          <p class="text-xs uppercase tracking-[0.2em] text-slate-400">${escapeHTML(String(label))}</p>
          <p class="mt-2 font-mono text-2xl text-white">${escapeHTML(String(value))}</p>
        </article>
      `)
      .join("");

    const sev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const finding of result.findings) {
      const s = String(finding.severity || "").toUpperCase();
      if (sev[s] !== undefined) {
        sev[s] += 1;
      }
    }
    dom.findingsMeta.textContent = `Critical ${sev.CRITICAL}, High ${sev.HIGH}, Medium ${sev.MEDIUM}, Low ${sev.LOW} | Domains ${result.totalDomains}`;
  }

  function renderFindings(findings) {
    state.visibleFindings = findings;

    if (!findings.length) {
      dom.resultsBody.innerHTML = "<tr><td colspan='7' class='px-3 py-6 text-center text-slate-400'>No findings</td></tr>";
      dom.contextPanel.classList.add("hidden");
      return;
    }

    dom.resultsBody.innerHTML = findings.map((f, idx) => `
      <tr data-idx="${idx}" class="cursor-pointer transition hover:bg-slate-800/60">
        <td class="px-3 py-2"><span class="rounded-full px-2 py-0.5 text-xs font-semibold ${severityBadgeClass(String(f.severity || "MEDIUM").toUpperCase())}">${escapeHTML(String(f.severity || "MEDIUM").toUpperCase())}</span></td>
        <td class="px-3 py-2 font-mono text-xs text-emerald-200">${escapeHTML(String(f.riskScore || 0))}</td>
        <td class="px-3 py-2 text-slate-200">${escapeHTML(f.patternName)}</td>
        <td class="max-w-[170px] truncate px-3 py-2 font-mono text-xs text-cyan-200">${escapeHTML(f.domain || "N/A")}</td>
        <td class="max-w-[260px] truncate px-3 py-2 font-mono text-xs text-slate-300">${escapeHTML(f.source)}</td>
        <td class="px-3 py-2 font-mono text-xs text-slate-300">${f.lineNumber}:${f.column}</td>
        <td class="max-w-[300px] truncate px-3 py-2 font-mono text-xs text-slate-300">${escapeHTML(truncate(f.matchedText, 100))}</td>
      </tr>
    `).join("");

    dom.resultsBody.querySelectorAll("tr[data-idx]").forEach((row) => {
      row.addEventListener("click", () => {
        const idx = Number(row.getAttribute("data-idx"));
        showContext(findings[idx]);
      });
    });
  }

  function applyViewFilters() {
    const severity = dom.severityFilter.value;
    const query = dom.searchFilter.value.trim().toLowerCase();

    const visible = state.findings.filter((finding) => {
      if (severity !== "ALL" && String(finding.severity || "").toUpperCase() !== severity) {
        return false;
      }

      if (!query) {
        return true;
      }

      const bag = [
        finding.domain,
        finding.source,
        finding.patternName,
        finding.matchedText,
        finding.description,
        finding.category,
        finding.cwe,
        finding.riskScore
      ].join(" ").toLowerCase();

      return bag.includes(query);
    });

    renderFindings(visible);
  }

  function showContext(finding) {
    if (!finding) {
      dom.contextPanel.classList.add("hidden");
      return;
    }

    dom.contextTitle.textContent = `${finding.patternName} [risk ${finding.riskScore || 0}] - ${finding.domain} - ${finding.source}:${finding.lineNumber}:${finding.column}`;
    dom.contextContent.textContent = finding.context || "N/A";
    dom.contextPanel.classList.remove("hidden");
  }

  function exportJSON() {
    if (!state.lastResult) {
      appendLog("No crawl scan result to export.");
      return;
    }
    downloadBlob(`crawl-scan-report-${timestamp()}.json`, "application/json", JSON.stringify(state.lastResult, null, 2));
  }

  function exportCSV() {
    if (!state.visibleFindings.length) {
      appendLog("No visible findings to export.");
      return;
    }

    const headers = ["severity", "risk_score", "domain", "pattern_name", "source", "line", "column", "matched_text", "line_variant", "entropy", "category", "cwe"];
    const rows = [headers.join(",")];

    for (const f of state.visibleFindings) {
      rows.push([
        f.severity,
        f.riskScore,
        f.domain,
        f.patternName,
        f.source,
        f.lineNumber,
        f.column,
        f.matchedText,
        f.lineVariant,
        f.entropy,
        f.category,
        f.cwe
      ].map(csvCell).join(","));
    }

    downloadBlob(`crawl-scan-report-${timestamp()}.csv`, "text/csv", rows.join("\n"));
  }

  function clearAll() {
    dom.domainList.value = "";
    dom.crawlDepth.value = "4";
    dom.crawlMaxURLs.value = "600";
    dom.crawlMaxNew.value = "250";
    dom.domainConcurrency.value = "4";
    dom.crawlConcurrency.value = "8";
    dom.fetchConcurrency.value = "12";
    dom.maxQueue.value = "12000";
    dom.includeSubdomains.checked = false;
    dom.onlyLikelyFiles.checked = true;
    dom.includePassiveSources.checked = true;
    dom.jsEndpointMining.checked = true;
    dom.ignoreQueryParams.checked = true;
    dom.includeRegex.value = "";
    dom.excludeRegex.value = "";
    dom.fetchTimeout.value = "20";
    dom.maxBodyMB.value = "5";
    dom.falsePositiveFilter.checked = true;
    dom.contextFilter.checked = true;
    dom.fastMode.checked = true;
    dom.deepAnalysis.checked = true;
    dom.entropyFilter.checked = true;
    dom.contextLines.value = "1";
    dom.lineLimit.value = "5000";
    dom.entropyMin.value = "3.2";
    dom.severityFilter.value = "ALL";
    dom.searchFilter.value = "";
    dom.runLog.textContent = "";

    state.findings = [];
    state.visibleFindings = [];
    state.lastResult = null;

    renderSummary(null);
    renderFindings([]);
    setStatus("Idle", 0);
    dom.findingsMeta.textContent = "Run a crawl scan to see results.";
  }

  function loadSampleDomains() {
    dom.domainList.value = [
      "https://example.com",
      "https://www.iana.org"
    ].join("\n");
    appendLog("Sample domain list loaded.");
  }

  function setBusy(busy) {
    dom.scanBtn.disabled = busy;
    dom.scanBtn.classList.toggle("opacity-60", busy);
    dom.scanBtn.classList.toggle("cursor-not-allowed", busy);
  }

  function setStatus(label, percent) {
    const p = Math.max(0, Math.min(100, percent));
    dom.statusText.textContent = label;
    dom.progressText.textContent = `${p}%`;
    dom.progressBar.style.width = `${p}%`;
  }

  function appendLog(message) {
    const time = new Date().toLocaleTimeString();
    dom.runLog.textContent += `[${time}] ${message}\n`;
    dom.runLog.scrollTop = dom.runLog.scrollHeight;
  }

  function prepareContentForScan(rawURL, contentType, content, options) {
    if (options && options.fastMode) {
      return content;
    }
    if (looksLikeJavaScript(rawURL, contentType)) {
      return beautifyJS(content);
    }
    return content;
  }

  function beautifyJS(content) {
    let out = "";
    let indent = 0;
    let inString = false;
    let stringChar = "";
    let prev = "";

    for (let i = 0; i < content.length; i += 1) {
      const c = content[i];

      if (!inString && (c === "\"" || c === "'" || c === "`")) {
        inString = true;
        stringChar = c;
      } else if (inString && c === stringChar && prev !== "\\") {
        inString = false;
        stringChar = "";
      }

      if (!inString) {
        if (c === "{" || c === "[" || c === "(") {
          out += `${c}\n${" ".repeat((indent + 1) * 2)}`;
          indent += 1;
          prev = c;
          continue;
        }
        if (c === "}" || c === "]" || c === ")") {
          indent = Math.max(0, indent - 1);
          out += `\n${" ".repeat(indent * 2)}${c}`;
          prev = c;
          continue;
        }
        if (c === ",") {
          out += `${c}\n${" ".repeat(indent * 2)}`;
          prev = c;
          continue;
        }
      }

      out += c;
      prev = c;
    }

    return out.replace(/\n{3,}/g, "\n\n").replace(/ {2,}/g, " ");
  }

  async function fetchURLContent(targetURL, timeoutSec, maxBodyBytes) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutSec * 1000);

    try {
      const response = await fetch(targetURL, {
        method: "GET",
        signal: controller.signal,
        credentials: "omit",
        redirect: "follow"
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const contentType = response.headers.get("content-type") || "";
      const text = await response.text();
      const bytes = new TextEncoder().encode(text).length;

      if (bytes > maxBodyBytes) {
        throw new Error(`Body too large (${bytes} > ${maxBodyBytes})`);
      }

      return { content: text, contentType };
    } catch (err) {
      if (err.name === "AbortError") {
        throw new Error(`timeout after ${timeoutSec}s`);
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  function extractURLsFromContent(baseURL, content, crawlOptions) {
    const found = [];
    const text = String(content || "");
    resetRegexState(htmlLinkRegex);
    resetRegexState(htmlFormActionRegex);
    resetRegexState(absoluteURLRegex);
    resetRegexState(sourceMapRegex);
    resetRegexState(quotedPathRegex);
    resetRegexState(jsCallURLRegex);
    resetRegexState(jsImportRegex);
    resetRegexState(endpointLiteralRegex);

    let m;
    while ((m = htmlLinkRegex.exec(text)) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[1]);
      if (candidate) {
        found.push(candidate);
      }
    }

    while ((m = htmlFormActionRegex.exec(text)) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[1]);
      if (candidate) {
        found.push(candidate);
      }
    }

    while ((m = absoluteURLRegex.exec(text)) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[0]);
      if (candidate) {
        found.push(candidate);
      }
    }

    while ((m = sourceMapRegex.exec(text)) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[1]);
      if (candidate) {
        found.push(candidate);
      }
    }

    while ((m = quotedPathRegex.exec(text)) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[1]);
      if (candidate) {
        found.push(candidate);
      }
    }

    if (crawlOptions && crawlOptions.jsEndpointMining) {
      while ((m = jsCallURLRegex.exec(text)) !== null) {
        const candidate = normalizeDiscoveredURL(baseURL, m[1]);
        if (candidate) {
          found.push(candidate);
        }
      }
      while ((m = jsImportRegex.exec(text)) !== null) {
        const candidate = normalizeDiscoveredURL(baseURL, m[1]);
        if (candidate) {
          found.push(candidate);
        }
      }
      while ((m = endpointLiteralRegex.exec(text)) !== null) {
        const candidate = normalizeDiscoveredURL(baseURL, m[1]);
        if (candidate) {
          found.push(candidate);
        }
      }
    }

    return uniqueStrings(found);
  }

  function extractURLsFromRobots(baseURL, content) {
    const out = [];
    const lines = String(content || "").split(/\r?\n/);

    for (const rawLine of lines) {
      const line = rawLine.split("#")[0].trim();
      if (!line) {
        continue;
      }

      const parts = line.split(":");
      if (parts.length < 2) {
        continue;
      }

      const key = parts[0].trim().toLowerCase();
      const value = parts.slice(1).join(":").trim();
      if (!value) {
        continue;
      }

      if (key === "allow" || key === "disallow" || key === "sitemap") {
        const candidate = normalizeDiscoveredURL(baseURL, value);
        if (candidate) {
          out.push(candidate);
        }
      }
    }

    return uniqueStrings(out);
  }

  function extractURLsFromSitemap(baseURL, content) {
    const out = [];
    resetRegexState(sitemapLocRegex);

    let m;
    while ((m = sitemapLocRegex.exec(String(content || ""))) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[1]);
      if (candidate) {
        out.push(candidate);
      }
    }

    return uniqueStrings(out);
  }

  function normalizeDiscoveredURL(baseURL, candidate) {
    const value = String(candidate || "").trim();
    if (!value) {
      return "";
    }
    if (/^(?:javascript|mailto|tel|data):/i.test(value)) {
      return "";
    }

    try {
      let parsed;
      if (/^https?:\/\//i.test(value)) {
        parsed = new URL(value);
      } else if (value.startsWith("//")) {
        const base = new URL(baseURL);
        parsed = new URL(`${base.protocol}${value}`);
      } else {
        parsed = new URL(value, baseURL);
      }

      if (!/^https?:$/i.test(parsed.protocol)) {
        return "";
      }

      parsed.hash = "";
      return parsed.toString();
    } catch (err) {
      return "";
    }
  }

  function normalizeBaseURL(input) {
    const trimmed = String(input || "").trim();
    if (!trimmed) {
      throw new Error("empty domain");
    }

    let candidate = trimmed;
    if (!/^https?:\/\//i.test(candidate)) {
      candidate = `https://${candidate}`;
    }

    const parsed = new URL(candidate);
    parsed.hash = "";
    return parsed.toString();
  }

  function buildURLScopeKey(rawURL, ignoreQueryParams) {
    try {
      const parsed = new URL(rawURL);
      parsed.hash = "";
      if (ignoreQueryParams) {
        parsed.search = "";
      }

      const pathname = parsed.pathname.length > 1 && parsed.pathname.endsWith("/")
        ? parsed.pathname.slice(0, -1)
        : parsed.pathname;
      parsed.pathname = pathname || "/";

      return parsed.toString();
    } catch (err) {
      return String(rawURL || "").trim();
    }
  }

  function scoreCrawlTarget(rawURL, depth) {
    const value = String(rawURL || "").toLowerCase();
    let score = Math.max(1, 100 - depth * 7);

    if (isLikelyScanTarget(value, "")) {
      score += 40;
    }
    if (looksLikeJavaScript(value, "")) {
      score += 18;
    }
    if (/(?:\/api\/|\/graphql|\/config|\/admin|\/internal|\/auth)/.test(value)) {
      score += 22;
    }
    if (/(?:\?|&)(?:token|key|api|auth)=/.test(value)) {
      score += 10;
    }
    if (isRobotsURL(value) || isSitemapURL(value)) {
      score += 16;
    }

    return score;
  }

  function buildPassiveSeedURLs(baseURL) {
    const defaults = [
      "/robots.txt",
      "/sitemap.xml",
      "/sitemap_index.xml",
      "/wp-sitemap.xml",
      "/.well-known/security.txt"
    ];

    const out = [];
    for (const p of defaults) {
      try {
        out.push(new URL(p, baseURL).toString());
      } catch (err) {
        // ignore
      }
    }
    return uniqueStrings(out);
  }

  function isRobotsURL(rawURL) {
    return /\/robots\.txt(?:$|[?#])/i.test(String(rawURL || ""));
  }

  function isSitemapURL(rawURL) {
    return /\/sitemap(?:[_-]index)?\.xml(?:$|[?#])/i.test(String(rawURL || ""));
  }

  function isInDomainScope(rawURL, rootHost, includeSubdomains) {
    try {
      const parsed = new URL(rawURL);
      if (parsed.hostname === rootHost) {
        return true;
      }
      return Boolean(includeSubdomains && parsed.hostname.endsWith(`.${rootHost}`));
    } catch (err) {
      return false;
    }
  }

  function passesCrawlFilters(urlValue, crawlOptions) {
    if (crawlOptions.includeRegex && !crawlOptions.includeRegex.test(urlValue)) {
      return false;
    }
    if (crawlOptions.excludeRegex && crawlOptions.excludeRegex.test(urlValue)) {
      return false;
    }
    return true;
  }

  function prioritizeCrawlTargets(urls, prioritizeLikely) {
    if (!prioritizeLikely) {
      return uniqueStrings(urls);
    }

    return uniqueStrings(urls).sort((a, b) => {
      const aLikely = isLikelyScanTarget(a, "") ? 1 : 0;
      const bLikely = isLikelyScanTarget(b, "") ? 1 : 0;
      if (aLikely !== bLikely) {
        return bLikely - aLikely;
      }
      return a.localeCompare(b);
    });
  }

  function buildDisclosureURLs(baseURL) {
    const out = [];
    for (const pathPart of data.disclosurePaths || []) {
      try {
        out.push(new URL(pathPart, baseURL).toString());
      } catch (err) {
        // ignore
      }
    }
    return out;
  }

  function shouldScanResponse(rawURL, contentType) {
    const ct = String(contentType || "").toLowerCase();
    if (looksLikeJavaScript(rawURL, ct)) {
      return true;
    }
    if (ct.includes("application/json") || ct.includes("text/plain") || ct.includes("text/html") || ct.includes("application/xml") || ct.includes("text/xml")) {
      return true;
    }
    return /\.(json|txt|xml|env|log|ya?ml|md)(?:$|[?#])/i.test(rawURL);
  }

  function isLikelyScanTarget(rawURL, contentType) {
    if (looksLikeJavaScript(rawURL, contentType)) {
      return true;
    }
    return /\.(json|txt|xml|env|log|ya?ml|md|config|conf|ini|properties|sh)(?:$|[?#])/i.test(String(rawURL || ""));
  }

  function looksLikeJavaScript(rawURL, contentType) {
    const urlValue = String(rawURL || "").toLowerCase();
    const ct = String(contentType || "").toLowerCase();
    if (ct.includes("javascript") || ct.includes("ecmascript") || ct.includes("application/x-javascript")) {
      return true;
    }
    return /\.(js|mjs|cjs|jsx|ts|tsx|map)(?:$|[?#])/i.test(urlValue);
  }

  function looksLikePage(rawURL) {
    return /\/(?:$|[?#])/.test(rawURL) || /\.(?:html?|php|aspx?|jsp)(?:$|[?#])/i.test(rawURL);
  }

  function dedupeSources(sources) {
    const out = [];
    const seen = new Set();

    for (const item of sources) {
      if (!item || !item.source) {
        continue;
      }

      const key = `${item.domain || ""}|${item.source}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      out.push(item);
    }

    return out.sort((a, b) => {
      const d = String(a.domain || "").localeCompare(String(b.domain || ""));
      if (d !== 0) {
        return d;
      }
      return a.source.localeCompare(b.source);
    });
  }

  function buildLineVariants(line, deepAnalysis) {
    const variants = [{ kind: "raw", value: line }];
    if (!deepAnalysis) {
      return variants;
    }

    const seen = new Set([line]);
    const escaped = decodeEscapedSequences(line);
    if (escaped && !seen.has(escaped)) {
      seen.add(escaped);
      variants.push({ kind: "decoded-escape", value: escaped });
    }

    const uri = decodeURISafe(line);
    if (uri && !seen.has(uri)) {
      seen.add(uri);
      variants.push({ kind: "decoded-uri", value: uri });
    }

    for (const decoded of decodeBase64Chunks(line, 4)) {
      if (!seen.has(decoded)) {
        seen.add(decoded);
        variants.push({ kind: "decoded-base64", value: decoded });
      }
    }

    return variants;
  }

  function decodeEscapedSequences(value) {
    const line = String(value || "");
    if (!/\\[ux]/.test(line)) {
      return "";
    }
    return line
      .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
  }

  function decodeURISafe(value) {
    const line = String(value || "");
    if (!/%[0-9a-fA-F]{2}/.test(line)) {
      return "";
    }
    try {
      return decodeURIComponent(line);
    } catch (err) {
      return "";
    }
  }

  function decodeBase64Chunks(value, maxChunks) {
    const out = [];
    const chunks = String(value || "").match(/[A-Za-z0-9+/]{20,}={0,2}/g) || [];
    for (const chunk of chunks) {
      if (out.length >= maxChunks) {
        break;
      }
      const decoded = decodeBase64Safe(chunk);
      if (!decoded) {
        continue;
      }
      if (decoded.length < 10) {
        continue;
      }
      if (!/[A-Za-z]/.test(decoded)) {
        continue;
      }
      out.push(decoded);
    }
    return out;
  }

  function decodeBase64Safe(chunk) {
    try {
      if (chunk.length % 4 !== 0) {
        return "";
      }
      const decoded = atob(chunk);
      if (!/^[\x09\x0A\x0D\x20-\x7E]+$/.test(decoded)) {
        return "";
      }
      return decoded;
    } catch (err) {
      return "";
    }
  }

  function findMatchColumn(rawLine, matchedText, fallback) {
    const idx = rawLine.indexOf(matchedText);
    if (idx >= 0) {
      return idx;
    }
    return Math.max(0, fallback);
  }

  function getContext(lines, lineNum, contextSize) {
    if (lineNum < 1 || lineNum > lines.length) {
      return "";
    }
    const start = Math.max(0, lineNum - 1 - contextSize);
    const end = Math.min(lines.length, lineNum + contextSize);
    const out = [];
    for (let i = start; i < end; i += 1) {
      const prefix = i === lineNum - 1 ? "> " : "  ";
      out.push(`${prefix}${lines[i]}`);
    }
    return out.join("\n");
  }

  function detectFunctionBehind(line, matchStart) {
    const matches = [];
    const re = new RegExp(functionCallRegex.source, "g");
    let m;
    while ((m = re.exec(line)) !== null) {
      matches.push({ name: m[1], index: m.index });
      if (re.lastIndex === m.index) {
        re.lastIndex += 1;
      }
    }
    if (!matches.length) {
      return "N/A";
    }

    let best = "";
    let bestDistance = Number.MAX_SAFE_INTEGER;
    for (const item of matches) {
      if (item.index <= matchStart) {
        const dist = matchStart - item.index;
        if (dist < bestDistance) {
          bestDistance = dist;
          best = item.name;
        }
      }
    }
    return best || matches[0].name || "N/A";
  }

  function calculateShannonEntropy(value) {
    const input = String(value || "");
    if (!input) {
      return 0;
    }

    const freq = new Map();
    for (const ch of input) {
      freq.set(ch, (freq.get(ch) || 0) + 1);
    }

    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / input.length;
      entropy -= p * Math.log2(p);
    }

    return Number(entropy.toFixed(3));
  }

  function byId(id) {
    const el = document.getElementById(id);
    if (!el) {
      throw new Error(`Missing element #${id}`);
    }
    return el;
  }

  function defaultString(value, fallback) {
    return String(value || "").trim() ? String(value) : fallback;
  }

  function countLines(content) {
    return String(content || "").split("\n").length;
  }

  function formatDuration(ms) {
    if (ms < 1000) {
      return `${ms}ms`;
    }
    return `${(ms / 1000).toFixed(2)}s`;
  }

  function escapeHTML(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll("\"", "&quot;")
      .replaceAll("'", "&#39;");
  }

  function csvCell(value) {
    return `"${String(value == null ? "" : value).replace(/"/g, "\"\"")}"`;
  }

  function severityBadgeClass(sev) {
    switch (sev) {
      case "CRITICAL":
        return "bg-red-900/50 text-red-200 border border-red-700/60";
      case "HIGH":
        return "bg-orange-900/50 text-orange-200 border border-orange-700/60";
      case "MEDIUM":
        return "bg-amber-900/50 text-amber-200 border border-amber-700/60";
      case "LOW":
        return "bg-emerald-900/50 text-emerald-200 border border-emerald-700/60";
      default:
        return "bg-slate-800 text-slate-200 border border-slate-600";
    }
  }

  function clampNumber(v, min, max, fallback) {
    if (!Number.isFinite(v)) {
      return fallback;
    }
    if (v < min) {
      return min;
    }
    if (v > max) {
      return max;
    }
    return v;
  }

  function truncate(value, limit) {
    const s = String(value || "");
    if (s.length <= limit) {
      return s;
    }
    return `${s.slice(0, Math.max(0, limit - 3))}...`;
  }

  function uniqueStrings(values) {
    return Array.from(new Set((values || []).filter(Boolean)));
  }

  function timestamp() {
    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  }

  function downloadBlob(filename, mime, content) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function resetRegexState(re) {
    re.lastIndex = 0;
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function runConcurrent(items, limit, worker) {
    const concurrency = Math.max(1, Math.min(limit, items.length || 1));
    let index = 0;

    async function runner() {
      while (index < items.length) {
        const current = index;
        index += 1;
        await worker(items[current], current);
      }
    }

    const runners = [];
    for (let i = 0; i < concurrency; i += 1) {
      runners.push(runner());
    }
    await Promise.all(runners);
  }
})();
