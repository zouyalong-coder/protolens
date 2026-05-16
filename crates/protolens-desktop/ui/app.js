const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const interfaceSelect = document.querySelector("#interfaceSelect");
const filterInput = document.querySelector("#filterInput");
const payloadLimitInput = document.querySelector("#payloadLimitInput");
const countInput = document.querySelector("#countInput");
const pcapOutputInput = document.querySelector("#pcapOutputInput");
const pcapLoadInput = document.querySelector("#pcapLoadInput");
const startButton = document.querySelector("#startButton");
const stopButton = document.querySelector("#stopButton");
const savePcapPathButton = document.querySelector("#savePcapPathButton");
const loadPcapPathButton = document.querySelector("#loadPcapPathButton");
const loadPcapButton = document.querySelector("#loadPcapButton");
const refreshButton = document.querySelector("#refreshButton");
const clearButton = document.querySelector("#clearButton");
const linkSelect = document.querySelector("#linkSelect");
const linkCount = document.querySelector("#linkCount");
const statusText = document.querySelector("#status");
const events = document.querySelector("#events");
const links = document.querySelector("#links");

let eventCount = 0;
let selectedLinkKey = null;
const linkStates = new Map();

function setRunning(running) {
  startButton.disabled = running;
  stopButton.disabled = !running;
  savePcapPathButton.disabled = running;
  loadPcapPathButton.disabled = running;
  loadPcapButton.disabled = running;
}

function setStatus(message) {
  statusText.textContent = message;
}

function endpoint(value) {
  if (!value) return "unknown";
  return `${value.address}:${value.port}`;
}

function normalizeType(value) {
  if (!value) return value;
  return value
    .replace(/-/g, "_")
    .replace(/[A-Z]/g, (letter, index) => `${index === 0 ? "" : "_"}${letter.toLowerCase()}`);
}

function eventKind(event) {
  const kind = event.kind ?? {};
  if (kind.type) return { ...kind, type: normalizeType(kind.type) };

  const variant = Object.keys(kind)[0];
  if (!variant) return kind;

  const type = normalizeType(variant);
  return { type, ...kind[variant] };
}

function endpointSortKey(value) {
  return `${value.address}:${String(value.port).padStart(5, "0")}`;
}

function tcpFlags(tcp) {
  if (!tcp) return "none";
  return (
    Object.entries(tcp)
      .filter(([, enabled]) => enabled)
      .map(([name]) => name.toUpperCase())
      .join(" ") || "none"
  );
}

function packetLabel(tcp, payload) {
  if (!tcp) return "Packet";
  if (tcp.rst) return "TCP RST";
  if (tcp.syn && tcp.ack) return "TCP SYN-ACK";
  if (tcp.syn) return "TCP SYN";
  if (tcp.fin) return tcp.ack ? "TCP FIN-ACK" : "TCP FIN";
  if (payload?.original_len > 0) return tcp.psh ? "TCP PSH data" : "TCP data";
  if (tcp.ack) return "TCP ACK";
  return "TCP segment";
}

function payloadLabel(payload) {
  if (!payload) return "payload 0B";
  return `payload ${payload.original_len}B${payload.truncated ? " truncated" : ""}`;
}

function layerDetail(packet) {
  if (!packet) return "layers=unknown";

  const linkProtocol = packet.link.protocol ? `/${packet.link.protocol}` : "";
  const hopLimit = packet.network.hop_limit == null ? "" : ` ttl=${packet.network.hop_limit}`;

  return [
    `L2 ${packet.link.medium}${linkProtocol} frame=${packet.link.frame_len}B hdr=${packet.link.header_len}B`,
    `L3 ${packet.network.protocol} packet=${packet.network.packet_len}B hdr=${packet.network.header_len}B${hopLimit}`,
    `L4 ${packet.transport.protocol} segment=${packet.transport.segment_len}B hdr=${packet.transport.header_len}B`,
  ].join(" | ");
}

function linkKey(flow) {
  if (!flow) return null;
  const endpoints = [flow.source, flow.destination].sort((left, right) =>
    endpointSortKey(left).localeCompare(endpointSortKey(right)),
  );
  return `${endpoint(endpoints[0])}<->${endpoint(endpoints[1])}`;
}

function orderedFlow(flow) {
  const endpoints = [flow.source, flow.destination].sort((left, right) =>
    endpointSortKey(left).localeCompare(endpointSortKey(right)),
  );
  const sourceIsLeft = endpoint(flow.source) === endpoint(endpoints[0]);
  return {
    left: endpoint(endpoints[0]),
    right: endpoint(endpoints[1]),
    arrow: sourceIsLeft ? "->" : "<-",
  };
}

function insertEventChronologically(row) {
  const timestamp = Number(row.dataset.timestamp);

  for (const existing of events.children) {
    if (timestamp < Number(existing.dataset.timestamp)) {
      events.insertBefore(row, existing);
      return;
    }
  }

  events.append(row);
}

function getLinkState(flow) {
  const key = linkKey(flow);
  if (!key) return null;

  const endpoints = [flow.source, flow.destination].sort((left, right) =>
    endpointSortKey(left).localeCompare(endpointSortKey(right)),
  );

  if (!linkStates.has(key)) {
    linkStates.set(key, {
      key,
      left: endpoint(endpoints[0]),
      right: endpoint(endpoints[1]),
      leftToRightPackets: 0,
      rightToLeftPackets: 0,
      leftToRightBytes: 0,
      rightToLeftBytes: 0,
      packets: 0,
      bytes: 0,
      client: null,
      server: null,
      phase: "observing",
    });
  }

  return linkStates.get(key);
}

function updateLink(flow, tcp, payload) {
  const state = getLinkState(flow);
  if (!state) return null;

  const size = payload?.original_len ?? 0;
  state.packets += 1;
  state.bytes += size;

  if (endpoint(flow.source) === state.left) {
    state.leftToRightPackets += 1;
    state.leftToRightBytes += size;
  } else {
    state.rightToLeftPackets += 1;
    state.rightToLeftBytes += size;
  }

  if (tcp?.syn && !tcp.ack) {
    state.client = endpoint(flow.source);
    state.server = endpoint(flow.destination);
    state.phase = "SYN sent";
  } else if (tcp?.syn && tcp.ack) {
    state.client ??= endpoint(flow.destination);
    state.server ??= endpoint(flow.source);
    state.phase = "SYN-ACK returned";
  } else if (tcp?.ack && state.phase === "SYN-ACK returned") {
    state.phase = "established";
  } else if (tcp?.rst) {
    state.phase = "reset";
  } else if (tcp?.fin) {
    state.phase = "closing";
  } else if (payload?.original_len > 0 && state.phase === "observing") {
    state.phase = "data";
  }

  renderLinks();
  return state.key;
}

function renderLinks() {
  const sorted = [...linkStates.values()].sort((left, right) => right.packets - left.packets);
  const previousValue = linkSelect.value;
  linkSelect.replaceChildren(new Option("All links", ""));
  links.replaceChildren();
  linkCount.textContent = String(sorted.length);

  for (const link of sorted) {
    const title = link.client && link.server ? `${link.client} -> ${link.server}` : `${link.left} <-> ${link.right}`;
    const option = new Option(title, link.key);
    linkSelect.append(option);

    const button = document.createElement("button");
    button.className = `link-filter${selectedLinkKey === link.key ? " active" : ""}`;
    button.innerHTML = `
      <span class="link-filter-title"></span>
      <span class="link-filter-meta"></span>
    `;
    button.querySelector(".link-filter-title").textContent = title;
    button.querySelector(".link-filter-meta").textContent =
      `${link.phase} | ${link.packets} packets, ${link.bytes} bytes | ` +
      `${link.leftToRightPackets}/${link.leftToRightBytes}B -> | ` +
      `<- ${link.rightToLeftPackets}/${link.rightToLeftBytes}B`;
    button.addEventListener("click", () => selectLink(link.key));
    links.append(button);
  }

  linkSelect.value = selectedLinkKey && linkStates.has(selectedLinkKey) ? selectedLinkKey : previousValue;
}

function selectLink(key) {
  selectedLinkKey = key;
  linkSelect.value = key ?? "";

  for (const row of events.children) {
    row.hidden = selectedLinkKey !== null && row.dataset.linkKey !== selectedLinkKey;
  }

  renderLinks();
}

function summarizeEvent(event) {
  const kind = eventKind(event);

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
    const flags = tcpFlags(kind.tcp);
    const label = packetLabel(kind.tcp, payload);
    const flowDisplay = flow ? orderedFlow(flow) : null;
    const title = flowDisplay ? `${label}: ${flowDisplay.left} ${flowDisplay.arrow} ${flowDisplay.right}` : label;
    const preview = payload?.preview ? ` preview=${JSON.stringify(payload.preview)}` : "";
    return {
      title,
      detail: `${layerDetail(kind.packet)} | flags=${flags} | ${payloadLabel(payload)}${preview}`,
      badges: [label, payloadLabel(payload), flags],
    };
  }

  if (kind.type === "error") {
    return { title: "Pipeline error", detail: kind.message };
  }

  return { title: kind.type, detail: JSON.stringify(kind) };
}

function appendEvent(event) {
  eventCount += 1;
  const kind = eventKind(event);
  const summary = summarizeEvent(event);
  const flow = kind.type === "interface_packet" ? kind.flow : null;
  const rowLinkKey = flow ? updateLink(flow, kind.tcp, kind.payload) : "";
  const row = document.createElement("article");
  row.className = "event";
  row.dataset.linkKey = rowLinkKey || "";
  row.dataset.timestamp = String(Date.parse(event.timestamp));
  row.hidden = selectedLinkKey !== null && row.dataset.linkKey !== selectedLinkKey;
  row.innerHTML = `
    <div class="event-header">
      <span>#${eventCount} ${new Date(event.timestamp).toLocaleTimeString()}</span>
      <span>${kind.type}</span>
    </div>
    <div class="event-main"></div>
    <div class="event-tags"></div>
    <div class="event-detail"></div>
  `;
  row.querySelector(".event-main").textContent = summary.title;
  const tags = row.querySelector(".event-tags");
  for (const badge of summary.badges ?? []) {
    const tag = document.createElement("span");
    tag.className = "event-tag";
    tag.textContent = badge;
    tags.append(tag);
  }
  row.querySelector(".event-detail").textContent = summary.detail;
  insertEventChronologically(row);
}

function clearEvents() {
  eventCount = 0;
  selectedLinkKey = null;
  linkStates.clear();
  links.replaceChildren();
  events.replaceChildren();
  linkSelect.replaceChildren(new Option("All links", ""));
  linkCount.textContent = "0";
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
        pcapOutputPath: pcapOutputInput.value.trim() || null,
      },
    });
    setRunning(true);
    setStatus(pcapOutputInput.value.trim() ? `Capture running, saving ${pcapOutputInput.value.trim()}` : "Capture running");
  } catch (error) {
    setStatus(`Failed to start: ${error}`);
  }
}

async function stopCapture() {
  await invoke("stop_capture");
  setStatus("Stopping capture...");
}

async function chooseSavePcapPath() {
  try {
    const path = await invoke("select_save_pcap_path");
    if (path) {
      pcapOutputInput.value = path;
      setStatus(`Will save next capture to ${path}`);
    }
  } catch (error) {
    setStatus(`Failed to choose save path: ${error}`);
  }
}

async function chooseLoadPcapPath() {
  try {
    const path = await invoke("select_load_pcap_path");
    if (path) {
      pcapLoadInput.value = path;
      setStatus(`Selected ${path}`);
    }
  } catch (error) {
    setStatus(`Failed to choose pcap file: ${error}`);
  }
}

async function loadPcap() {
  const payloadLimit = Number.parseInt(payloadLimitInput.value, 10);
  const path = pcapLoadInput.value.trim();
  if (!path) {
    setStatus("PCAP path is required");
    return;
  }

  clearEvents();
  setStatus("Loading pcap...");
  try {
    const count = await invoke("load_capture_file", {
      request: {
        path,
        payloadLimit: Number.isFinite(payloadLimit) ? payloadLimit : 4096,
      },
    });
    setStatus(`Loaded ${count} events from ${path}`);
  } catch (error) {
    setStatus(`Failed to load pcap: ${error}`);
  }
}

startButton.addEventListener("click", startCapture);
stopButton.addEventListener("click", stopCapture);
savePcapPathButton.addEventListener("click", chooseSavePcapPath);
loadPcapPathButton.addEventListener("click", chooseLoadPcapPath);
loadPcapButton.addEventListener("click", loadPcap);
refreshButton.addEventListener("click", loadInterfaces);
clearButton.addEventListener("click", clearEvents);
linkSelect.addEventListener("change", () => selectLink(linkSelect.value || null));

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
