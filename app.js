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
    scanning: false,
    selectedFinding: null
  };

  const dom = {
    patternCountHeader: byId("patternCountHeader"),
    urlList: byId("urlList"),
    fetchTimeout: byId("fetchTimeout"),
    maxBodyMB: byId("maxBodyMB"),
    fileInput: byId("fileInput"),
    fileMeta: byId("fileMeta"),
    pasteName: byId("pasteName"),
    pasteType: byId("pasteType"),
    pastedContent: byId("pastedContent"),
    crawlEnabled: byId("crawlEnabled"),
    crawlBaseURL: byId("crawlBaseURL"),
    crawlDepth: byId("crawlDepth"),
    crawlMaxURLs: byId("crawlMaxURLs"),
    crawlMaxNew: byId("crawlMaxNew"),
    falsePositiveFilter: byId("falsePositiveFilter"),
    contextFilter: byId("contextFilter"),
    contextLines: byId("contextLines"),
    lineLimit: byId("lineLimit"),
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
    exportCSV: byId("exportCSV"),
    exportTXT: byId("exportTXT")
  };

  const functionCallRegex = /([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(/g;
  const htmlLinkRegex = /(?:href|src)\s*=\s*["']([^"']+)["']/gi;
  const absoluteURLRegex = /https?:\/\/[^\s"'<>]+/g;
  const sourceMapRegex = /sourceMappingURL=([^\s]+)/gm;
  const quotedPathRegex = /["'](\/[^"'?#\s]{1,200}(?:\?[^"'\s]*)?)["']/g;

  init();

  function init() {
    compilePatterns();
    state.patternMap = new Map(data.patterns.map((p) => [p.name, p]));

    dom.fileInput.addEventListener("change", () => {
      const files = Array.from(dom.fileInput.files || []);
      dom.fileMeta.textContent = files.length
        ? `${files.length} file(s) selected, ${files.reduce((n, f) => n + f.size, 0)} bytes total.`
        : "No files selected.";
    });

    dom.scanBtn.addEventListener("click", runScan);
    dom.clearBtn.addEventListener("click", clearAll);
    dom.sampleBtn.addEventListener("click", loadSample);
    dom.severityFilter.addEventListener("change", applyViewFilters);
    dom.searchFilter.addEventListener("input", applyViewFilters);
    dom.exportJSON.addEventListener("click", exportJSON);
    dom.exportCSV.addEventListener("click", exportCSV);
    dom.exportTXT.addEventListener("click", exportTXT);

    setStatus("Idle", 0);
    renderSummary(null);
    renderFindings([]);
    appendLog(`Ready. Loaded ${state.compiledPatterns.length}/${data.patterns.length} patterns.`);
  }

  function compilePatterns() {
    const compiled = [];
    let invalid = 0;

    for (const p of data.patterns) {
      try {
        const re = new RegExp(p.regex, p.flags || "g");
        compiled.push({ ...p, regexObj: re });
      } catch (err) {
        invalid += 1;
      }
    }

    state.compiledPatterns = compiled;
    dom.patternCountHeader.textContent = `${compiled.length} loaded`;

    if (invalid > 0) {
      appendLog(`Skipped ${invalid} regex pattern(s) that are unsupported in browser RegExp.`);
    }
  }

  async function runScan() {
    if (state.scanning) {
      return;
    }

    state.scanning = true;
    setStatus("Collecting sources...", 1);
    dom.scanBtn.disabled = true;
    dom.scanBtn.classList.add("opacity-60", "cursor-not-allowed");
    dom.runLog.textContent = "";

    const startedAt = performance.now();
    let discoveredURLs = 0;

    try {
      const options = readOptions();
      const initialSources = [];

      const pasted = dom.pastedContent.value;
      if (pasted.trim()) {
        initialSources.push({
          source: (dom.pasteName.value || "pasted-input.txt").trim(),
          contentType: (dom.pasteType.value || "text/plain").trim(),
          content: pasted
        });
      }

      const uploaded = await loadUploadedFiles();
      initialSources.push(...uploaded);

      const urlTargets = parseURLList(dom.urlList.value);
      if (urlTargets.length) {
        appendLog(`Fetching ${urlTargets.length} URL target(s)...`);
        const fetchedURLSources = await fetchScanTargets(urlTargets, options, 8);
        discoveredURLs += urlTargets.length;
        initialSources.push(...fetchedURLSources);
      }

      if (options.crawl.enabled) {
        const baseURL = normalizeBaseURL(options.crawl.baseURL);
        appendLog(`Crawl enabled for ${baseURL} (depth=${options.crawl.depth}, max=${options.crawl.maxURLs}).`);

        const discovered = await crawlDomain(baseURL, options);
        discoveredURLs += discovered.length;

        const fetchedCrawlSources = await fetchScanTargets(discovered, options, 8);
        initialSources.push(...fetchedCrawlSources);

        const additional = discoverAdditionalTargetsFromFetched(baseURL, fetchedCrawlSources, options.crawl.maxNew);
        if (additional.length) {
          appendLog(`Expanded from fetched content: +${additional.length} URL(s).`);
          discoveredURLs += additional.length;
          const expandedSources = await fetchScanTargets(additional, options, 8);
          initialSources.push(...expandedSources);
        }
      }

      const scanSources = dedupeSources(initialSources)
        .map((s) => ({ ...s, content: prepareContentForScan(s.source, s.contentType, s.content) }))
        .filter((s) => s.content.trim().length > 0);

      if (!scanSources.length) {
        appendLog("No scanable source content available.");
        state.findings = [];
        state.lastResult = {
          totalFiles: 0,
          discoveredURLs,
          totalMatches: 0,
          findings: [],
          scanDurationMs: Math.round(performance.now() - startedAt),
          patternsUsed: state.compiledPatterns.length,
          falsePositives: 0
        };
        renderSummary(state.lastResult);
        renderFindings([]);
        setStatus("No sources", 100);
        return;
      }

      const totalLines = scanSources.reduce((sum, s) => sum + countLines(s.content), 0);
      let scannedLines = 0;
      const findings = [];

      appendLog(`Scanning ${scanSources.length} source(s), ${totalLines} total line(s), ${state.compiledPatterns.length} patterns.`);

      for (let i = 0; i < scanSources.length; i += 1) {
        const sourceObj = scanSources[i];
        setStatus(`Scanning ${sourceObj.source}`, Math.floor((i / scanSources.length) * 100));

        const sourceFindings = await scanContent(sourceObj, options, () => {
          scannedLines += 1;
          const pct = totalLines > 0 ? Math.min(100, Math.floor((scannedLines / totalLines) * 100)) : 100;
          setStatus(`Scanning ${sourceObj.source}`, pct);
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

      const durationMs = Math.round(performance.now() - startedAt);
      const result = {
        totalFiles: scanSources.length,
        discoveredURLs,
        totalMatches: filtered.length,
        findings: filtered,
        scanDurationMs: durationMs,
        patternsUsed: state.compiledPatterns.length,
        falsePositives: beforeFilter - filtered.length
      };

      state.findings = filtered;
      state.lastResult = result;

      renderSummary(result);
      applyViewFilters();
      appendLog(`Done in ${formatDuration(durationMs)}. Findings: ${filtered.length}. Filtered: ${result.falsePositives}.`);
      setStatus("Scan complete", 100);
    } catch (err) {
      appendLog(`Error: ${err.message || String(err)}`);
      setStatus("Failed", 100);
    } finally {
      state.scanning = false;
      dom.scanBtn.disabled = false;
      dom.scanBtn.classList.remove("opacity-60", "cursor-not-allowed");
    }
  }

  function readOptions() {
    const timeoutSec = clampNumber(Number(dom.fetchTimeout.value), 3, 120, 20);
    const maxBodyMB = clampNumber(Number(dom.maxBodyMB.value), 1, 25, 4);

    return {
      timeoutSec,
      maxBodyBytes: Math.floor(maxBodyMB * 1024 * 1024),
      lineLimit: clampNumber(Number(dom.lineLimit.value), 300, 30000, 5000),
      contextLines: clampNumber(Number(dom.contextLines.value), 0, 5, 1),
      filters: {
        falsePositive: dom.falsePositiveFilter.checked,
        contextWhitelist: dom.contextFilter.checked
      },
      crawl: {
        enabled: dom.crawlEnabled.checked,
        baseURL: dom.crawlBaseURL.value.trim(),
        depth: clampNumber(Number(dom.crawlDepth.value), 1, 6, 2),
        maxURLs: clampNumber(Number(dom.crawlMaxURLs.value), 10, 5000, 250),
        maxNew: clampNumber(Number(dom.crawlMaxNew.value), 0, 2000, 200)
      }
    };
  }

  async function loadUploadedFiles() {
    const files = Array.from(dom.fileInput.files || []);
    if (!files.length) {
      return [];
    }

    appendLog(`Reading ${files.length} uploaded file(s)...`);

    const results = await Promise.all(files.map(async (file) => {
      const content = await file.text();
      return {
        source: file.name,
        contentType: file.type || guessContentType(file.name),
        content
      };
    }));

    return results;
  }

  function parseURLList(raw) {
    const lines = raw
      .split(/\r?\n/)
      .map((v) => v.trim())
      .filter(Boolean);

    const unique = [];
    const seen = new Set();

    for (const line of lines) {
      try {
        const normalized = normalizeTargetURL(line);
        if (!seen.has(normalized)) {
          seen.add(normalized);
          unique.push(normalized);
        }
      } catch (err) {
        appendLog(`Invalid URL skipped: ${line}`);
      }
    }

    return unique;
  }

  async function fetchScanTargets(targetURLs, options, concurrency) {
    const sources = [];

    await runConcurrent(targetURLs, concurrency, async (targetURL) => {
      try {
        const { content, contentType } = await fetchURLContent(targetURL, options.timeoutSec, options.maxBodyBytes);
        if (!shouldScanResponse(targetURL, contentType)) {
          return;
        }
        sources.push({
          source: targetURL,
          contentType,
          content
        });
      } catch (err) {
        appendLog(`Fetch skipped: ${targetURL} -> ${err.message || String(err)}`);
      }
    });

    return sources.sort((a, b) => a.source.localeCompare(b.source));
  }

  async function crawlDomain(baseURL, options) {
    const root = new URL(baseURL);
    const rootHost = root.hostname;

    const queue = [{ url: baseURL, depth: 0 }];
    const visited = new Set([baseURL]);
    const discovered = [];

    while (queue.length > 0 && discovered.length < options.crawl.maxURLs) {
      const current = queue.shift();
      discovered.push(current.url);

      if (current.depth >= options.crawl.depth) {
        continue;
      }

      try {
        const { content } = await fetchURLContent(current.url, options.timeoutSec, options.maxBodyBytes);
        const extracted = extractURLsFromContent(current.url, content);

        for (const found of extracted) {
          if (!isInDomainScope(found, rootHost)) {
            continue;
          }
          if (visited.has(found)) {
            continue;
          }
          visited.add(found);
          queue.push({ url: found, depth: current.depth + 1 });
          if (visited.size >= options.crawl.maxURLs) {
            break;
          }
        }
      } catch (err) {
        appendLog(`Crawl miss: ${current.url} -> ${err.message || String(err)}`);
      }
    }

    for (const probe of buildDisclosureURLs(baseURL)) {
      if (discovered.length >= options.crawl.maxURLs) {
        break;
      }
      if (!visited.has(probe)) {
        visited.add(probe);
        discovered.push(probe);
      }
    }

    appendLog(`Crawl discovered ${discovered.length} URL(s).`);
    return uniqueStrings(discovered).slice(0, options.crawl.maxURLs);
  }

  function discoverAdditionalTargetsFromFetched(baseURL, fetchedSources, maxNew) {
    if (maxNew <= 0) {
      return [];
    }

    let rootHost = "";
    try {
      rootHost = new URL(baseURL).hostname;
    } catch (err) {
      return [];
    }

    const seen = new Set(fetchedSources.map((s) => s.source));
    const out = [];

    for (const source of fetchedSources) {
      const extracted = extractURLsFromContent(source.source, source.content);
      for (const urlValue of extracted) {
        if (!isInDomainScope(urlValue, rootHost)) {
          continue;
        }
        if (seen.has(urlValue)) {
          continue;
        }

        seen.add(urlValue);
        out.push(urlValue);

        if (looksLikeJavaScript(urlValue, "")) {
          const mapCandidate = `${urlValue}.map`;
          if (!seen.has(mapCandidate)) {
            seen.add(mapCandidate);
            out.push(mapCandidate);
          }
        }

        if (out.length >= maxNew) {
          return out.slice(0, maxNew);
        }
      }
    }

    return out;
  }

  async function scanContent(sourceObj, options, progressTick) {
    const findings = [];
    const lines = sourceObj.content.split("\n");

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx += 1) {
      let scanLine = lines[lineIdx];
      if (scanLine.length > options.lineLimit) {
        scanLine = scanLine.slice(0, options.lineLimit);
      }

      for (const p of state.compiledPatterns) {
        const regex = p.regexObj;
        regex.lastIndex = 0;
        let match;

        while ((match = regex.exec(scanLine)) !== null) {
          const matchedText = match[0] || "";
          if (matchedText.length >= 3) {
            const startIdx = match.index;
            findings.push({
              lineNumber: lineIdx + 1,
              column: startIdx + 1,
              source: sourceObj.source,
              patternName: p.name,
              matchedText,
              context: getContext(lines, lineIdx + 1, options.contextLines),
              severity: defaultString(p.severity, "MEDIUM"),
              confidence: defaultString(p.confidence, "MEDIUM"),
              category: defaultString(p.category, "Secrets Exposure"),
              cwe: defaultString(p.cwe, "N/A"),
              description: defaultString(p.description, p.name),
              function: detectFunctionBehind(scanLine, startIdx)
            });
          }

          if (regex.lastIndex === match.index) {
            regex.lastIndex += 1;
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
      const prefix = finding.matchedText.slice(0, 20);
      const key = `${finding.source}:${finding.patternName}:${finding.lineNumber}:${finding.column}:${prefix}`;

      if (seen.has(key)) {
        continue;
      }

      const pattern = state.patternMap.get(finding.patternName) || { name: finding.patternName };
      if (isLikelyFalsePositive(finding.matchedText, pattern)) {
        continue;
      }

      seen.add(key);
      filtered.push(finding);
    }

    return filtered;
  }

  function filterContextWhitelist(findings) {
    const terms = (data.contextWhitelist || []).map((s) => String(s).toLowerCase());
    return findings.filter((f) => {
      const lowerCtx = String(f.context || "").toLowerCase();
      for (const term of terms) {
        if (lowerCtx.includes(term)) {
          return false;
        }
      }
      return true;
    });
  }

  function isLikelyFalsePositive(matchValue, pattern) {
    const lower = String(matchValue).toLowerCase();

    for (const term of data.whitelistPatterns || []) {
      if (lower.includes(String(term).toLowerCase())) {
        return true;
      }
    }

    if (pattern.minLength && matchValue.length < pattern.minLength) {
      return true;
    }
    if (pattern.maxLength && matchValue.length > pattern.maxLength) {
      return true;
    }

    try {
      const hash = CryptoJS.SHA256(matchValue).toString();
      if (hash.includes("aaaaa")) {
        return true;
      }
    } catch (err) {
      // ignore hash errors
    }

    let repeated = 0;
    for (let i = 1; i < matchValue.length; i += 1) {
      if (matchValue[i] === matchValue[i - 1]) {
        repeated += 1;
        if (repeated > matchValue.length / 3) {
          return true;
        }
      } else {
        repeated = 0;
      }
    }

    return false;
  }

  function getContext(lines, lineNum, contextSize) {
    if (lineNum < 1 || lineNum > lines.length) {
      return "";
    }

    const start = Math.max(0, lineNum - 1 - contextSize);
    const end = Math.min(lines.length, lineNum + contextSize);
    const parts = [];

    for (let i = start; i < end; i += 1) {
      const prefix = i === lineNum - 1 ? "> " : "  ";
      parts.push(`${prefix}${lines[i]}`);
    }

    return parts.join("\n");
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

    let fallback = matches[0].name;
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

    return best || fallback || "N/A";
  }

  function prepareContentForScan(rawURL, contentType, content) {
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

      if (!inString && (c === '"' || c === "'" || c === "`")) {
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

    return out
      .replace(/\n{3,}/g, "\n\n")
      .replace(/ {2,}/g, " ");
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
        throw new Error(`Body too large (${bytes} bytes > ${maxBodyBytes})`);
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

  function extractURLsFromContent(baseURL, content) {
    const found = [];

    resetRegexState(htmlLinkRegex);
    resetRegexState(absoluteURLRegex);
    resetRegexState(sourceMapRegex);
    resetRegexState(quotedPathRegex);

    let m;
    while ((m = htmlLinkRegex.exec(content)) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[1]);
      if (candidate) {
        found.push(candidate);
      }
    }

    while ((m = absoluteURLRegex.exec(content)) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[0]);
      if (candidate) {
        found.push(candidate);
      }
    }

    while ((m = sourceMapRegex.exec(content)) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[1]);
      if (candidate) {
        found.push(candidate);
      }
    }

    while ((m = quotedPathRegex.exec(content)) !== null) {
      const candidate = normalizeDiscoveredURL(baseURL, m[1]);
      if (candidate) {
        found.push(candidate);
      }
    }

    return uniqueStrings(found);
  }

  function normalizeDiscoveredURL(baseURL, candidate) {
    const value = String(candidate || "").trim();
    if (!value) {
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
      parsed.hash = "";
      return parsed.toString();
    } catch (err) {
      return "";
    }
  }

  function normalizeBaseURL(input) {
    const trimmed = String(input || "").trim();
    if (!trimmed) {
      throw new Error("crawl base URL is required when crawl is enabled");
    }

    let candidate = trimmed;
    if (!/^https?:\/\//i.test(candidate)) {
      candidate = `https://${candidate}`;
    }

    const parsed = new URL(candidate);
    parsed.hash = "";
    return parsed.toString();
  }

  function normalizeTargetURL(input) {
    const trimmed = String(input || "").trim();
    if (!trimmed) {
      throw new Error("empty URL value");
    }

    let candidate = trimmed;
    if (!/^https?:\/\//i.test(candidate)) {
      candidate = `https://${candidate}`;
    }

    const parsed = new URL(candidate);
    parsed.hash = "";
    return parsed.toString();
  }

  function isInDomainScope(rawURL, rootHost) {
    try {
      const parsed = new URL(rawURL);
      return parsed.hostname === rootHost;
    } catch (err) {
      return false;
    }
  }

  function buildDisclosureURLs(baseURL) {
    const paths = data.disclosurePaths || [];
    const out = [];

    for (const pathPart of paths) {
      try {
        out.push(new URL(pathPart, baseURL).toString());
      } catch (err) {
        // ignore invalid path
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

  function looksLikeJavaScript(rawURL, contentType) {
    const urlValue = String(rawURL || "").toLowerCase();
    const ct = String(contentType || "").toLowerCase();

    if (ct.includes("javascript") || ct.includes("ecmascript") || ct.includes("application/x-javascript")) {
      return true;
    }

    return /\.(js|mjs|cjs|jsx|ts|tsx|map)(?:$|[?#])/i.test(urlValue);
  }

  function dedupeSources(sources) {
    const out = [];
    const seen = new Set();

    for (const item of sources) {
      if (!item || !item.source) {
        continue;
      }
      const key = `${item.source}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      out.push(item);
    }

    return out.sort((a, b) => a.source.localeCompare(b.source));
  }

  function renderSummary(result) {
    if (!result) {
      dom.summaryCards.innerHTML = "";
      return;
    }

    const severityCounts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    };

    for (const finding of result.findings) {
      const s = String(finding.severity || "").toUpperCase();
      if (severityCounts[s] !== undefined) {
        severityCounts[s] += 1;
      }
    }

    const cards = [
      ["Sources", result.totalFiles],
      ["Discovered URLs", result.discoveredURLs],
      ["Findings", result.totalMatches],
      ["Patterns", result.patternsUsed],
      ["Filtered", result.falsePositives],
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

    dom.findingsMeta.textContent = `Critical ${severityCounts.CRITICAL}, High ${severityCounts.HIGH}, Medium ${severityCounts.MEDIUM}, Low ${severityCounts.LOW}`;
  }

  function renderFindings(findings) {
    state.visibleFindings = findings;

    if (!findings.length) {
      dom.resultsBody.innerHTML = "<tr><td colspan='7' class='px-3 py-6 text-center text-slate-400'>No findings</td></tr>";
      dom.contextPanel.classList.add("hidden");
      return;
    }

    const rows = findings.map((f, idx) => {
      const sev = String(f.severity || "MEDIUM").toUpperCase();
      const badgeClass = severityBadgeClass(sev);
      const displayMatch = truncate(f.matchedText, 100);

      return `
        <tr data-idx="${idx}" class="cursor-pointer transition hover:bg-slate-800/60">
          <td class="px-3 py-2"><span class="rounded-full px-2 py-0.5 text-xs font-semibold ${badgeClass}">${escapeHTML(sev)}</span></td>
          <td class="px-3 py-2 text-slate-200">${escapeHTML(f.patternName)}</td>
          <td class="max-w-[280px] truncate px-3 py-2 font-mono text-xs text-slate-300">${escapeHTML(f.source)}</td>
          <td class="px-3 py-2 font-mono text-xs text-slate-300">${f.lineNumber}:${f.column}</td>
          <td class="px-3 py-2 font-mono text-xs text-cyan-200">${escapeHTML(f.function || "N/A")}</td>
          <td class="max-w-[300px] truncate px-3 py-2 font-mono text-xs text-slate-300">${escapeHTML(displayMatch)}</td>
          <td class="px-3 py-2 text-xs text-slate-300">${escapeHTML(`${f.category} / ${f.cwe}`)}</td>
        </tr>
      `;
    });

    dom.resultsBody.innerHTML = rows.join("");

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

    const visible = state.findings.filter((f) => {
      if (severity !== "ALL" && String(f.severity || "").toUpperCase() !== severity) {
        return false;
      }

      if (!query) {
        return true;
      }

      const bag = [
        f.patternName,
        f.source,
        f.matchedText,
        f.category,
        f.cwe,
        f.function,
        f.description
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

    state.selectedFinding = finding;
    dom.contextTitle.textContent = `${finding.patternName} - ${finding.source}:${finding.lineNumber}:${finding.column}`;
    dom.contextContent.textContent = finding.context || "N/A";
    dom.contextPanel.classList.remove("hidden");
  }

  function exportJSON() {
    if (!state.lastResult) {
      appendLog("No scan result to export.");
      return;
    }
    const content = JSON.stringify(state.lastResult, null, 2);
    downloadBlob(`secret-finder-report-${timestamp()}.json`, "application/json", content);
  }

  function exportCSV() {
    const findings = state.visibleFindings;
    if (!findings.length) {
      appendLog("No visible findings to export as CSV.");
      return;
    }

    const headers = [
      "severity",
      "confidence",
      "pattern_name",
      "source",
      "line",
      "column",
      "function",
      "category",
      "cwe",
      "description",
      "matched_text"
    ];

    const rows = [headers.join(",")];

    for (const f of findings) {
      const values = [
        f.severity,
        f.confidence,
        f.patternName,
        f.source,
        f.lineNumber,
        f.column,
        f.function,
        f.category,
        f.cwe,
        f.description,
        f.matchedText
      ].map(csvCell);

      rows.push(values.join(","));
    }

    downloadBlob(`secret-finder-report-${timestamp()}.csv`, "text/csv", rows.join("\n"));
  }

  function exportTXT() {
    if (!state.lastResult) {
      appendLog("No scan result to export.");
      return;
    }

    const out = [];
    out.push("Secret Finder Web Report");
    out.push(`Sources: ${state.lastResult.totalFiles}`);
    out.push(`Discovered URLs: ${state.lastResult.discoveredURLs}`);
    out.push(`Findings: ${state.lastResult.totalMatches}`);
    out.push(`Patterns: ${state.lastResult.patternsUsed}`);
    out.push(`Filtered: ${state.lastResult.falsePositives}`);
    out.push(`Duration: ${formatDuration(state.lastResult.scanDurationMs)}`);
    out.push("");

    for (const f of state.visibleFindings) {
      out.push(`[${f.severity}] ${f.patternName}`);
      out.push(`Source: ${f.source}:${f.lineNumber}:${f.column}`);
      out.push(`Function: ${f.function}`);
      out.push(`Category/CWE: ${f.category}/${f.cwe}`);
      out.push(`Description: ${f.description}`);
      out.push(`Matched: ${f.matchedText}`);
      out.push("Context:");
      out.push(f.context || "N/A");
      out.push("-".repeat(72));
    }

    downloadBlob(`secret-finder-report-${timestamp()}.txt`, "text/plain", out.join("\n"));
  }

  function clearAll() {
    dom.urlList.value = "";
    dom.fileInput.value = "";
    dom.fileMeta.textContent = "No files selected.";
    dom.pasteName.value = "pasted-input.txt";
    dom.pasteType.value = "text/plain";
    dom.pastedContent.value = "";
    dom.crawlEnabled.checked = false;
    dom.crawlBaseURL.value = "";
    dom.severityFilter.value = "ALL";
    dom.searchFilter.value = "";

    state.findings = [];
    state.visibleFindings = [];
    state.lastResult = null;

    renderSummary(null);
    renderFindings([]);
    setStatus("Idle", 0);
    dom.runLog.textContent = "";
    dom.findingsMeta.textContent = "Run a scan to see results.";
  }

  function loadSample() {
    dom.urlList.value = "";
    dom.pasteName.value = "sample-app.js";
    dom.pasteType.value = "application/javascript";
    dom.pastedContent.value = [
      "const apiKey = 'sk_live_1234567890abcdefghijklmnopqrstuvwxyz';",
      "const cfg = {",
      "  github_client_secret: 'abc123abc123abc123abc123abc123abc123abc1',",
      "  endpoint: 'https://api.example.com/data?token=abcdefghijklmnopqrstuvwx1234'",
      "};",
      "app.get('/admin', (req, res) => {",
      "  const cmd = exec(req.query.cmd);",
      "  res.send(cmd);",
      "});",
      "setTimeout('alert(1)', 1000);"
    ].join("\n");

    appendLog("Sample content loaded.");
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
    if (!content) {
      return 0;
    }
    return content.split("\n").length;
  }

  function formatDuration(ms) {
    if (ms < 1000) {
      return `${ms}ms`;
    }
    return `${(ms / 1000).toFixed(2)}s`;
  }

  function csvCell(value) {
    const s = String(value == null ? "" : value).replace(/"/g, '""');
    return `"${s}"`;
  }

  function escapeHTML(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
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

  function guessContentType(source) {
    if (/(\.js|\.mjs|\.cjs|\.jsx|\.ts|\.tsx|\.map)$/i.test(source)) {
      return "application/javascript";
    }
    if (/\.json$/i.test(source)) {
      return "application/json";
    }
    if (/\.(xml)$/i.test(source)) {
      return "application/xml";
    }
    if (/\.(html?)$/i.test(source)) {
      return "text/html";
    }
    return "text/plain";
  }

  function looksLikePage(rawURL) {
    return /\/(?:$|[?#])/.test(rawURL) || /\.(?:html?|php|aspx?|jsp)(?:$|[?#])/i.test(rawURL);
  }

  function uniqueStrings(values) {
    return Array.from(new Set(values.filter(Boolean)));
  }

  function truncate(value, limit) {
    const s = String(value || "");
    if (s.length <= limit) {
      return s;
    }
    return `${s.slice(0, Math.max(0, limit - 3))}...`;
  }

  function timestamp() {
    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
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
