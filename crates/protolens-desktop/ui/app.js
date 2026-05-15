const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const interfaceSelect = document.querySelector("#interfaceSelect");
const filterInput = document.querySelector("#filterInput");
const payloadLimitInput = document.querySelector("#payloadLimitInput");
const countInput = document.querySelector("#countInput");
const startButton = document.querySelector("#startButton");
const stopButton = document.querySelector("#stopButton");
const refreshButton = document.querySelector("#refreshButton");
const clearButton = document.querySelector("#clearButton");
const allLinksButton = document.querySelector("#allLinksButton");
const statusText = document.querySelector("#status");
const events = document.querySelector("#events");
const links = document.querySelector("#links");

let eventCount = 0;
let selectedLinkKey = null;
const linkStates = new Map();

function setRunning(running) {
  startButton.disabled = running;
  stopButton.disabled = !running;
}

function setStatus(message) {
  statusText.textContent = message;
}

function endpoint(value) {
  if (!value) return "unknown";
  return `${value.address}:${value.port}`;
}

function endpointSortKey(value) {
  return `${value.address}:${String(value.port).padStart(5, "0")}`;
}

function linkKey(flow) {
  if (!flow) return null;
  const endpoints = [flow.source, flow.destination].sort((left, right) =>
    endpointSortKey(left).localeCompare(endpointSortKey(right)),
  );
  return `${endpoint(endpoints[0])}<->${endpoint(endpoints[1])}`;
}

function getLinkState(flow) {
  const key = linkKey(flow);
  if (!key) return null;

  if (!linkStates.has(key)) {
    linkStates.set(key, {
      key,
      firstSource: endpoint(flow.source),
      firstDestination: endpoint(flow.destination),
      packets: 0,
      bytes: 0,
    });
  }

  return linkStates.get(key);
}

function updateLink(flow, payload) {
  const state = getLinkState(flow);
  if (!state) return null;

  state.packets += 1;
  state.bytes += payload?.original_len ?? 0;
  renderLinks();
  return state.key;
}

function renderLinks() {
  const sorted = [...linkStates.values()].sort((left, right) => right.packets - left.packets);
  links.replaceChildren();

  for (const link of sorted) {
    const button = document.createElement("button");
    button.className = `link-filter${selectedLinkKey === link.key ? " active" : ""}`;
    button.innerHTML = `
      <span class="link-filter-title"></span>
      <span class="link-filter-meta"></span>
    `;
    button.querySelector(".link-filter-title").textContent = `${link.firstSource} -> ${link.firstDestination}`;
    button.querySelector(".link-filter-meta").textContent = `${link.packets} packets, ${link.bytes} bytes`;
    button.addEventListener("click", () => selectLink(link.key));
    links.append(button);
  }
}

function selectLink(key) {
  selectedLinkKey = key;
  allLinksButton.classList.toggle("active", selectedLinkKey === null);

  for (const row of events.children) {
    row.hidden = selectedLinkKey !== null && row.dataset.linkKey !== selectedLinkKey;
  }

  renderLinks();
}

function summarizeEvent(event) {
  const kind = event.kind;

  if (kind.type === "capture_started") {
    return { title: `Capture started (${kind.mode})`, detail: event.source_id };
  }

  if (kind.type === "dns_resolved") {
    const names = kind.resolutions.map((item) => `${item.hostname} -> ${item.address}`).join(", ");
    return { title: "DNS resolved", detail: names || "empty response" };
  }

  if (kind.type === "interface_packet") {
    const flow = kind.flow;
    const payload = kind.payload;
    const flags = kind.tcp
      ? Object.entries(kind.tcp)
          .filter(([, enabled]) => enabled)
          .map(([name]) => name.toUpperCase())
          .join(" ") || "none"
      : "none";
    const size = payload ? `${payload.original_len} bytes${payload.truncated ? " truncated" : ""}` : "no payload";
    const title = flow ? `${endpoint(flow.source)} -> ${endpoint(flow.destination)}` : "Packet";
    const preview = payload?.preview ? ` preview=${JSON.stringify(payload.preview)}` : "";
    return { title, detail: `flags=${flags} payload=${size}${preview}` };
  }

  if (kind.type === "error") {
    return { title: "Pipeline error", detail: kind.message };
  }

  return { title: kind.type, detail: JSON.stringify(kind) };
}

function appendEvent(event) {
  eventCount += 1;
  const summary = summarizeEvent(event);
  const flow = event.kind.type === "interface_packet" ? event.kind.flow : null;
  const rowLinkKey = flow ? updateLink(flow, event.kind.payload) : "";
  const row = document.createElement("article");
  row.className = "event";
  row.dataset.linkKey = rowLinkKey || "";
  row.hidden = selectedLinkKey !== null && row.dataset.linkKey !== selectedLinkKey;
  row.innerHTML = `
    <div class="event-header">
      <span>#${eventCount} ${new Date(event.timestamp).toLocaleTimeString()}</span>
      <span>${event.kind.type}</span>
    </div>
    <div class="event-main"></div>
    <div class="event-detail"></div>
  `;
  row.querySelector(".event-main").textContent = summary.title;
  row.querySelector(".event-detail").textContent = summary.detail;
  events.prepend(row);
}

async function loadInterfaces() {
  setStatus("Loading interfaces...");
  try {
    const interfaces = await invoke("list_interfaces");
    interfaceSelect.replaceChildren();

    for (const item of interfaces) {
      const option = document.createElement("option");
      option.value = item.name;
      option.textContent = item.description ? `${item.name} - ${item.description}` : item.name;
      interfaceSelect.append(option);
    }

    setStatus(interfaces.length ? `Loaded ${interfaces.length} interfaces` : "No interfaces found");
  } catch (error) {
    setStatus(`Failed to load interfaces: ${error}`);
  }
}

async function startCapture() {
  const payloadLimit = Number.parseInt(payloadLimitInput.value, 10);
  const count = countInput.value ? Number.parseInt(countInput.value, 10) : null;

  setStatus("Starting capture...");
  try {
    await invoke("start_capture", {
      request: {
        interface: interfaceSelect.value,
        filter: filterInput.value || "tcp or udp port 53",
        payloadLimit: Number.isFinite(payloadLimit) ? payloadLimit : 4096,
        count: Number.isFinite(count) ? count : null,
      },
    });
    setRunning(true);
    setStatus("Capture running");
  } catch (error) {
    setStatus(`Failed to start: ${error}`);
  }
}

async function stopCapture() {
  await invoke("stop_capture");
  setStatus("Stopping capture...");
}

startButton.addEventListener("click", startCapture);
stopButton.addEventListener("click", stopCapture);
refreshButton.addEventListener("click", loadInterfaces);
clearButton.addEventListener("click", () => {
  eventCount = 0;
  selectedLinkKey = null;
  linkStates.clear();
  links.replaceChildren();
  events.replaceChildren();
  allLinksButton.classList.add("active");
});
allLinksButton.addEventListener("click", () => selectLink(null));

listen("capture-event", (event) => appendEvent(event.payload));
listen("capture-error", (event) => {
  setRunning(false);
  setStatus(`Capture error: ${event.payload}`);
});
listen("capture-stopped", () => {
  setRunning(false);
  setStatus("Capture stopped");
});

loadInterfaces();
