
(pairs) => {
  const apply = () => {
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const seen = [];
    while (walk.nextNode()) seen.push(walk.currentNode);
    for (const node of seen) {
      let t = node.nodeValue;
      for (const [from, to] of pairs) { t = t.split(from).join(to); }
      if (t !== node.nodeValue) node.nodeValue = t;
    }
    for (const el of document.querySelectorAll("input")) {
      let v = el.value;
      for (const [from, to] of pairs) { v = v.split(from).join(to); }
      if (v !== el.value) el.value = v;
    }
  };
  apply();
  if (!window.__rw) {
    window.__rw = new MutationObserver(apply);
    window.__rw.observe(document.body, {childList: true, subtree: true});
  }
}
