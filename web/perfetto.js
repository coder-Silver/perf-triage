(function () {
  const UI = "https://ui.perfetto.dev";
  const UI_SRC = UI + "/#!/?mode=embedded";

  const DIRECTION_DIMENSIONS = {
    memory: ["内存"],
    cpu: ["CPU 使用率"],
    frame: ["显示卡顿"],
    sched: ["调度"],
    power: ["功耗"],
    system: ["系统异常"],
  };

  function cleanText(value) {
    const text = String(value == null ? "" : value).trim();
    return text === "未知" ? "" : text;
  }

  function evidenceLines(value) {
    const source = Array.isArray(value) ? value : (value ? [value] : []);
    const lines = [];
    for (const item of source) {
      const text = String(item == null ? "" : item).trim();
      if (!text || text.startsWith("文件 ") || lines.indexOf(text) !== -1) continue;
      lines.push(text);
    }
    return lines;
  }

  function conclusionLine(problem) {
    const event = cleanText(problem.event);
    const title = cleanText(problem.title);
    if (!event) return title;
    if (!title || event === title) return event;
    if (title.indexOf(event) !== -1) return title;
    if (event.indexOf(title) !== -1) return event;
    if (/\d/.test(event)) return event;
    return title.length >= event.length ? title : event;
  }

  function adviceLine(text) {
    const value = cleanText(text);
    const marker = "优化方向是";
    if (value.indexOf(marker) === -1) return value;
    const parts = [];
    for (const piece of value.split(marker).slice(1)) {
      const bit = piece.replace(/^[，,：:\s]+/, "").trim();
      if (bit && parts.indexOf(bit) === -1) parts.push(bit);
    }
    return parts.join(" ") || value;
  }

  function identityLine(process, pid) {
    const name = cleanText(process);
    const id = cleanText(pid);
    if (name && id) return name + "  ·  pid " + id;
    if (name) return name;
    return id ? "pid " + id : "";
  }

  function problemsFor(direction, problems, used) {
    const dims = DIRECTION_DIMENSIONS[direction.id] || [];
    const matched = [];
    for (const problem of problems) {
      if (!problem || used.has(problem)) continue;
      const level = String(problem.level || "");
      if (level !== "P0" && level !== "P1" && level !== "P2") continue;
      if (dims.indexOf(String(problem.dimension || "")) === -1) continue;
      used.add(problem);
      matched.push(problem);
    }
    return matched;
  }

  function evidenceFor(problem, direction, solo, taken) {
    const lines = [];
    function add(line) {
      if (!line || lines.indexOf(line) !== -1 || taken.has(line)) return;
      lines.push(line);
      taken.add(line);
    }
    const own = evidenceLines(problem.evidence);
    const pool = evidenceLines(direction.evidence);
    if (solo) {
      pool.forEach(add);
      own.forEach(add);
      return lines;
    }
    own.forEach(add);
    const name = cleanText(problem.process);
    const pid = cleanText(problem.pid);
    for (const line of pool) {
      const hitName = name.length > 1 && line.indexOf(name) !== -1;
      const hitPid = pid.length >= 3 && line.indexOf(pid) !== -1;
      if (hitName || hitPid) add(line);
    }
    return lines;
  }

  function appendEvidence(card, lines) {
    if (!lines.length) return;
    const details = document.createElement("details");
    details.className = "evidence";
    const summary = document.createElement("summary");
    summary.textContent = "原文";
    const pre = document.createElement("pre");
    pre.textContent = lines.join("\n");
    details.append(summary, pre);
    card.append(details);
  }

  function makeCard(fields) {
    const card = document.createElement("article");
    const level = fields.level || "";
    card.className = "dir-card" + (level ? " is-" + level.toLowerCase() : "");
    if (fields.directionId) card.dataset.direction = fields.directionId;
    const head = document.createElement("div");
    head.className = "dir-head";
    if (level) {
      const badge = document.createElement("span");
      badge.className = "badge " + level.toLowerCase();
      badge.textContent = level;
      head.append(badge);
    }
    const copy = document.createElement("div");
    copy.className = "dir-copy";
    const who = fields.who || "";
    const dimension = fields.dimension || "";
    if (who) {
      const proc = document.createElement("div");
      proc.className = "dir-proc";
      proc.textContent = who;
      copy.append(proc);
    }
    if (dimension && dimension !== who) {
      const dim = document.createElement("div");
      dim.className = who ? "dir-dim" : "dir-proc";
      dim.textContent = dimension;
      copy.append(dim);
    }
    if (copy.childNodes.length) head.append(copy);
    if (head.childNodes.length) card.append(head);
    const sentence = fields.conclusion || "";
    if (sentence && sentence !== dimension && sentence !== who) {
      const conclusion = document.createElement("p");
      conclusion.className = "dir-conclusion";
      conclusion.textContent = sentence;
      card.append(conclusion);
    }
    const advice = adviceLine(fields.advice);
    if (advice) {
      const note = document.createElement("p");
      note.className = "dir-advice";
      note.textContent = advice;
      card.append(note);
    }
    appendEvidence(card, fields.evidence || []);
    return card;
  }

  function renderDirections(side, analysis) {
    side.replaceChildren();
    const directions = ((analysis && analysis.directions) || []).filter((item) => item && item.present !== false);
    const problems = ((analysis && analysis.problems) || []).filter(Boolean);
    const intro = document.createElement("p");
    intro.className = "side-intro";
    intro.textContent = directions.length
      ? "只列出这次有数据的方向。"
      : "这次没有可以给出结论的方向。";
    side.append(intro);
    if (analysis && analysis.upgrade && String(analysis.upgrade).indexOf("未找到") === -1) {
      const version = document.createElement("details");
      version.className = "side-note";
      const summary = document.createElement("summary");
      summary.textContent = "版本";
      const body = document.createElement("p");
      body.textContent = String(analysis.upgrade);
      version.append(summary, body);
      side.append(version);
    }
    if (!directions.length) return;
    const used = new Set();
    const list = document.createElement("div");
    list.className = "dir-list";
    for (const item of directions) {
      const matched = problemsFor(item, problems, used);
      if (!matched.length) {
        let sentence = cleanText(item.conclusion).replace(/^严重程度\s*P[012]。\s*/, "");
        const level = /^P[012]$/.test(cleanText(item.severity)) ? cleanText(item.severity) : "";
        if (level) sentence = sentence.replace(new RegExp("^" + level + "\\s*"), "");
        list.append(makeCard({
          directionId: item.id || "",
          level: level,
          dimension: cleanText(item.title),
          conclusion: sentence,
          advice: item.advice,
          evidence: evidenceLines(item.evidence),
        }));
        continue;
      }
      const taken = new Set();
      const groups = matched.map((problem) => evidenceFor(problem, item, matched.length === 1, taken));
      if (matched.length > 1) {
        for (const line of evidenceLines(item.evidence)) {
          if (!taken.has(line) && groups[0].indexOf(line) === -1) groups[0].push(line);
        }
      }
      matched.forEach((problem, index) => {
        const level = /^P[012]$/.test(String(problem.level || "")) ? String(problem.level) : "";
        list.append(makeCard({
          directionId: item.id || "",
          level: level,
          who: identityLine(problem.process, problem.pid),
          dimension: cleanText(problem.dimension) || cleanText(item.title),
          conclusion: conclusionLine(problem),
          advice: problem.advice || item.advice,
          evidence: groups[index],
        }));
      });
    }
    side.append(list);
  }

  function createSession(frame, hooks) {
    const notify = (hooks && hooks.onStatus) || function () {};
    const timings = {
      uiStart: 0,
      uiLoad: 0,
      pong: 0,
      fileStart: 0,
      fileEnd: 0,
      posted: 0,
      error: "",
      phase: "idle",
      traceId: "",
    };
    let generation = 0;
    let pingTimer = 0;
    let pingTimeout = 0;
    let pingHandler = null;
    let bootingId = "";
    let epoch = 0;

    function snapshot() {
      const bootMs = timings.pong && timings.uiStart ? Math.round(timings.pong - timings.uiStart) : 0;
      const fileMs = timings.fileEnd && timings.fileStart ? Math.round(timings.fileEnd - timings.fileStart) : 0;
      const loadMs = timings.uiLoad && timings.uiStart ? Math.round(timings.uiLoad - timings.uiStart) : 0;
      const pongAfterLoadMs = timings.pong && timings.uiLoad ? Math.round(timings.pong - timings.uiLoad) : 0;
      return {
        uiStart: timings.uiStart,
        uiLoad: timings.uiLoad,
        pong: timings.pong,
        fileStart: timings.fileStart,
        fileEnd: timings.fileEnd,
        posted: timings.posted,
        error: timings.error,
        phase: timings.phase,
        traceId: timings.traceId,
        bootMs: bootMs,
        fileMs: fileMs,
        loadMs: loadMs,
        pongAfterLoadMs: pongAfterLoadMs,
      };
    }

    function publish() {
      if (hooks && hooks.onTimings) hooks.onTimings(snapshot());
    }

    function stopPing() {
      clearInterval(pingTimer);
      clearTimeout(pingTimeout);
      pingTimer = 0;
      pingTimeout = 0;
      if (pingHandler) window.removeEventListener("message", pingHandler);
      pingHandler = null;
    }

    function fail(gen, text) {
      if (gen !== generation) return;
      timings.phase = "error";
      timings.error = text;
      stopPing();
      notify(text);
      publish();
    }

    function ping(gen) {
      if (gen !== generation || !frame.contentWindow) return;
      if (String(frame.src || "").indexOf("ui.perfetto.dev") === -1) return;
      frame.contentWindow.postMessage("PING", UI);
    }

    function postBuffer(gen, trace, buffer) {
      if (gen !== generation || !buffer || !frame.contentWindow) return;
      frame.contentWindow.postMessage({
        perfetto: {
          buffer: buffer,
          title: trace.name,
          fileName: trace.name,
          keepApiOpen: true,
        },
      }, UI);
      timings.posted = performance.now();
      timings.phase = "ready";
      timings.error = "";
      bootingId = String(trace.id);
      notify("时间线已载入：" + (trace.label || trace.name));
      publish();
    }

    function fetchBuffer(gen, trace) {
      timings.fileStart = performance.now();
      timings.fileEnd = 0;
      publish();
      return fetch("/api/traces/" + encodeURIComponent(trace.id) + "/file", { cache: "no-store" }).then(function (response) {
        if (!response.ok) throw new Error("读取 trace 失败");
        return response.arrayBuffer();
      }).then(function (buffer) {
        if (gen !== generation) return null;
        timings.fileEnd = performance.now();
        publish();
        return buffer;
      });
    }

    function boot(gen, trace, fileTask, force) {
      timings.uiStart = timings.uiStart && !force ? timings.uiStart : performance.now();
      if (force) {
        timings.uiStart = performance.now();
        timings.uiLoad = 0;
        timings.pong = 0;
      }
      timings.posted = 0;
      timings.phase = "booting";
      notify("正在后台加载 Perfetto …");
      publish();
      stopPing();
      let ponged = false;
      pingHandler = function (event) {
        if (gen !== generation || ponged) return;
        if (event.source !== frame.contentWindow || event.data !== "PONG") return;
        ponged = true;
        frame.dataset.pong = "1";
        timings.pong = performance.now();
        timings.phase = "posting";
        stopPing();
        notify("Perfetto 已就绪，正在送入 trace …");
        publish();
        fileTask.then(function (buffer) {
          postBuffer(gen, trace, buffer);
        }).catch(function (error) {
          fail(gen, String((error && error.message) || error));
        });
      };
      window.addEventListener("message", pingHandler);
      pingTimeout = setTimeout(function () {
        fail(gen, "Perfetto 界面没有在限时内就绪。需要能访问 ui.perfetto.dev。打开时会再试一次。");
      }, 120000);
      frame.onload = function () {
        if (gen !== generation) return;
        if (String(frame.src || "").indexOf("ui.perfetto.dev") === -1) return;
        if (!timings.uiLoad) timings.uiLoad = performance.now();
        publish();
        ping(gen);
      };
      const hasUi = String(frame.src || "").indexOf("ui.perfetto.dev") !== -1;
      if (force || !hasUi) {
        frame.dataset.pong = "";
        frame.dataset.embedded = "1";
        if (force && hasUi) {
          frame.src = "about:blank";
          frame.addEventListener("load", function onBlank() {
            frame.removeEventListener("load", onBlank);
            if (gen !== generation) return;
            timings.uiStart = performance.now();
            frame.src = UI_SRC;
          });
        } else {
          frame.src = UI_SRC;
        }
      }
      ping(gen);
      pingTimer = setInterval(function () { ping(gen); }, 200);
    }

    function load(trace, options) {
      options = options || {};
      if (!trace || trace.id === undefined || trace.id === null) return;
      const id = String(trace.id);
      const nextEpoch = options.epoch == null ? epoch : options.epoch;
      const same = id === bootingId && nextEpoch === epoch;
      if (!options.force && same && (timings.phase === "booting" || timings.phase === "posting" || timings.phase === "ready")) {
        return;
      }
      generation += 1;
      const gen = generation;
      epoch = nextEpoch;
      bootingId = id;
      timings.traceId = id;
      timings.error = "";
      const reuse = !options.force && frame.dataset.pong === "1" && String(frame.src || "").indexOf("ui.perfetto.dev") !== -1;
      const fileTask = fetchBuffer(gen, trace);
      fileTask.catch(function (error) {
        fail(gen, String((error && error.message) || error));
      });
      if (reuse) {
        timings.phase = "posting";
        notify("正在把 trace 送入已打开的 Perfetto …");
        publish();
        fileTask.then(function (buffer) {
          postBuffer(gen, trace, buffer);
        }).catch(function (error) {
          fail(gen, String((error && error.message) || error));
        });
        return;
      }
      boot(gen, trace, fileTask, Boolean(options.force));
    }

    function cancel() {
      generation += 1;
      stopPing();
      timings.phase = "idle";
      publish();
    }

    return {
      load: load,
      cancel: cancel,
      phase: function () { return timings.phase; },
      snapshot: snapshot,
    };
  }

  window.PerfettoHost = {
    UI: UI,
    UI_SRC: UI_SRC,
    renderDirections: renderDirections,
    createSession: createSession,
  };
})();
