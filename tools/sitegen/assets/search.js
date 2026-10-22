// Catalog search: filters catalog/rules.json in the browser by text and by
// risk class. Each entry is {i: rule id, p: provider, o: operation,
// c: classes the rule can produce (its own first), k: approval card}.
(function () {
  "use strict";
  var input = document.getElementById("q");
  var results = document.getElementById("results");
  var count = document.getElementById("count");
  var chips = Array.prototype.slice.call(document.querySelectorAll(".chip[data-class]"));
  if (!input || !results || !count) return;

  var LIMIT = 60;
  var rules = null;
  var selected = {};
  var timer = 0;

  function fmt(n) { return n.toLocaleString("en-US"); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function haystack(r) {
    return (r.i + " " + r.p + " " + r.o + " " + (r.k || "")).toLowerCase();
  }

  function render() {
    if (!rules) return;
    var q = input.value.trim().toLowerCase();
    var terms = q ? q.split(/\s+/) : [];
    var classes = Object.keys(selected).filter(function (c) { return selected[c]; });
    results.textContent = "";
    if (!terms.length && !classes.length) {
      count.textContent = "Search " + fmt(rules.length) + " rules by operation, tool, rule id or card text, or pick a class.";
      return;
    }
    var hits = [];
    var joined = terms.join("");
    for (var n = 0; n < rules.length; n++) {
      var r = rules[n];
      if (classes.length && !r.c.some(function (c) { return classes.indexOf(c) >= 0; })) continue;
      var h = r._h || (r._h = haystack(r));
      var ok = true;
      for (var t = 0; t < terms.length; t++) {
        if (h.indexOf(terms[t]) < 0) { ok = false; break; }
      }
      if (!ok) continue;
      // Rank operation names over rule ids over card text, and an operation
      // spelled like the query ("delete volume" finds DeleteVolume) first.
      var op = r._o || (r._o = r.o.toLowerCase());
      var id = r.i.toLowerCase();
      var score = 0;
      for (t = 0; t < terms.length; t++) {
        if (op.indexOf(terms[t]) >= 0) score += 3;
        if (id.indexOf(terms[t]) >= 0) score += 2;
      }
      if (joined.length > 3) {
        var flat = op.replace(/[^a-z0-9]/g, "");
        if (flat.indexOf(joined) >= 0) score += 6;
        else if (terms.length === 2 && flat.indexOf(terms[1] + terms[0]) >= 0) score += 5;
      }
      hits.push({ r: r, s: score, n: n });
    }
    hits.sort(function (a, b) { return b.s - a.s || a.n - b.n; });
    hits = hits.map(function (x) { return x.r; });
    if (!hits.length) {
      count.textContent = "No rule matches. Try part of a path, a tool name or an AWS action.";
      return;
    }
    count.textContent = hits.length > LIMIT
      ? fmt(hits.length) + " rules match; showing the first " + LIMIT + ". Add a word to narrow it down."
      : (hits.length === 1 ? "1 rule matches." : fmt(hits.length) + " rules match.");
    var frag = document.createDocumentFragment();
    hits.slice(0, LIMIT).forEach(function (r) {
      var li = el("li");
      var a = el("a");
      a.href = encodeURIComponent(r.p) + ".html#" + encodeURIComponent(r.i);
      a.appendChild(el("span", "r-op", r.o));
      if (r.k) a.appendChild(el("span", "r-card", "“" + r.k + "”"));
      a.appendChild(el("span", "r-meta", r.i));
      var cls = el("span", "r-cls");
      r.c.slice(0, 3).forEach(function (c, idx) {
        var s = el("span", "cls c-" + c, c);
        if (idx > 0) s.title = "with some arguments";
        cls.appendChild(s);
      });
      a.appendChild(cls);
      li.appendChild(a);
      frag.appendChild(li);
    });
    results.appendChild(frag);
  }

  function remember() {
    try {
      var u = new URL(location.href);
      var q = input.value.trim();
      if (q) u.searchParams.set("q", q); else u.searchParams.delete("q");
      var cs = Object.keys(selected).filter(function (c) { return selected[c]; });
      if (cs.length) u.searchParams.set("class", cs.join(",")); else u.searchParams.delete("class");
      history.replaceState(null, "", u);
    } catch (e) { /* the page still works without a shareable URL */ }
  }

  function update() {
    clearTimeout(timer);
    timer = setTimeout(function () { render(); remember(); }, 80);
  }

  try {
    var params = new URL(location.href).searchParams;
    if (params.get("q")) input.value = params.get("q");
    (params.get("class") || "").split(",").forEach(function (c) { if (c) selected[c] = true; });
  } catch (e) { /* ignore a malformed URL */ }

  chips.forEach(function (b) {
    var c = b.getAttribute("data-class");
    b.setAttribute("aria-pressed", selected[c] ? "true" : "false");
    b.addEventListener("click", function () {
      selected[c] = !selected[c];
      b.setAttribute("aria-pressed", selected[c] ? "true" : "false");
      update();
    });
  });
  input.addEventListener("input", update);

  count.textContent = "Loading rules…";
  fetch("rules.json")
    .then(function (res) {
      if (!res.ok) throw new Error(res.status);
      return res.json();
    })
    .then(function (data) { rules = data; render(); })
    .catch(function () {
      count.textContent = "The rule index did not load. Browse by provider below, or search the YAML on GitHub.";
    });
})();
