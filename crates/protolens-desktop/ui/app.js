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
let selectedProtocolView = null;
const linkStates = new Map();
const capturedEvents = [];
const collapsedGroups = new Map();
let renderScheduled = false;
let needsLinkRender = false;
let needsEventRender = false;
let virtualScrollScheduled = false;
let currentVirtualState = null;

const VIRTUAL_EVENT_THRESHOLD = 1_200;
const VIRTUAL_OVERSCAN_PX = 900;
const ESTIMATED_EVENT_HEIGHT = 122;
const ESTIMATED_GROUP_HEIGHT = 42;

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

function protocolName(value) {
  if (!value) return "unknown";
  if (typeof value === "string") return normalizeType(value).toUpperCase();
  return normalizeType(String(value)).toUpperCase();
}

function linkProtocols(packet) {
  if (!packet) return [];

  const linkProtocol = packet.link.protocol ? protocolName(packet.link.protocol) : null;
  const linkLabel = linkProtocol
    ? `${protocolName(packet.link.medium)} / ${linkProtocol}`
    : protocolName(packet.link.medium);

  return [
    { layer: "L2", protocol: linkLabel },
    { layer: "L3", protocol: protocolName(packet.network.protocol) },
    { layer: "L4", protocol: protocolName(packet.transport.protocol) },
  ];
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

function timestampMillis(value) {
  if (typeof value === "number") return value;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
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
      protocols: {
        L2: new Set(),
        L3: new Set(),
        L4: new Set(),
      },
    });
  }

  return linkStates.get(key);
}

function updateLink(flow, tcp, payload, protocols) {
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

  for (const item of protocols) {
    state.protocols[item.layer].add(item.protocol);
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

  return state.key;
}

function protocolItems(link) {
  return Object.entries(link.protocols).flatMap(([layer, values]) =>
    [...values].sort().map((protocol) => ({ layer, protocol })),
  );
}

function isProtocolViewActive(linkKey, layer, protocol) {
  return (
    selectedProtocolView?.linkKey === linkKey &&
    selectedProtocolView.layer === layer &&
    selectedProtocolView.protocol === protocol
  );
}

function renderLinks() {
  const sorted = [...linkStates.values()].sort((left, right) => right.packets - left.packets);
  const previousValue = linkSelect.value;
  const optionFragment = document.createDocumentFragment();
  const linkFragment = document.createDocumentFragment();
  optionFragment.append(new Option("All links", ""));
  linkCount.textContent = String(sorted.length);

  for (const link of sorted) {
    const title = link.client && link.server ? `${link.client} -> ${link.server}` : `${link.left} <-> ${link.right}`;
    const option = new Option(title, link.key);
    optionFragment.append(option);

    const button = document.createElement("button");
    button.className = `link-filter${selectedLinkKey === link.key ? " active" : ""}`;
    button.innerHTML = `
      <span class="link-filter-title"></span>
      <span class="protocol-stack"></span>
      <span class="link-filter-meta"></span>
    `;
    button.querySelector(".link-filter-title").textContent = title;
    const protocolStack = button.querySelector(".protocol-stack");
    for (const item of protocolItems(link)) {
      const protocolButton = document.createElement("span");
      protocolButton.role = "button";
      protocolButton.tabIndex = 0;
      protocolButton.className =
        `protocol-chip${isProtocolViewActive(link.key, item.layer, item.protocol) ? " active" : ""}`;
      protocolButton.textContent = `${item.layer} ${item.protocol}`;
      protocolButton.title = `Group this link by ${item.layer} ${item.protocol}`;
      protocolButton.addEventListener("click", (event) => {
        event.stopPropagation();
        selectProtocolView(link.key, item.layer, item.protocol);
      });
      protocolButton.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          event.stopPropagation();
          selectProtocolView(link.key, item.layer, item.protocol);
        }
      });
      protocolStack.append(protocolButton);
    }
    button.querySelector(".link-filter-meta").textContent =
      `${link.phase} | ${link.packets} packets, ${link.bytes} bytes | ` +
      `${link.leftToRightPackets}/${link.leftToRightBytes}B -> | ` +
      `<- ${link.rightToLeftPackets}/${link.rightToLeftBytes}B`;
    button.addEventListener("click", () => selectLink(link.key));
    linkFragment.append(button);
  }

  linkSelect.replaceChildren(optionFragment);
  links.replaceChildren(linkFragment);
  linkSelect.value = selectedLinkKey && linkStates.has(selectedLinkKey) ? selectedLinkKey : previousValue;
}

function selectLink(key) {
  selectedLinkKey = key;
  selectedProtocolView = null;
  linkSelect.value = key ?? "";
  renderEvents();
  renderLinks();
}

function selectProtocolView(linkKey, layer, protocol) {
  const wasActive = isProtocolViewActive(linkKey, layer, protocol);
  selectedProtocolView = wasActive ? null : { linkKey, layer, protocol };
  selectedLinkKey = linkKey;
  linkSelect.value = linkKey;
  renderEvents();
  renderLinks();
}

function protocolViewKey() {
  if (!selectedProtocolView) return "all";
  return `${selectedProtocolView.linkKey}|${selectedProtocolView.layer}|${selectedProtocolView.protocol}`;
}

function groupStateKey(group) {
  return `${protocolViewKey()}|${group}`;
}

function isGroupCollapsed(group) {
  const key = groupStateKey(group);
  return collapsedGroups.has(key) ? collapsedGroups.get(key) : true;
}

function toggleGroup(group) {
  collapsedGroups.set(groupStateKey(group), !isGroupCollapsed(group));
  renderEvents();
}

function eventMatchesProtocol(item, view) {
  if (!view) return true;
  if (item.linkKey !== view.linkKey) return false;
  return item.protocols.some(
    (protocol) => protocol.layer === view.layer && protocol.protocol === view.protocol,
  );
}

function eventVisible(item) {
  if (selectedProtocolView) return eventMatchesProtocol(item, selectedProtocolView);
  return selectedLinkKey === null || item.linkKey === selectedLinkKey;
}

function tcpPhaseGroup(tcp, payload) {
  if (!tcp) return "Other";
  if (tcp.rst) return "Reset";
  if (tcp.syn) return "Handshake";
  if (tcp.fin) return "Teardown";
  if (payload?.original_len > 0) return "Transfer";
  return "Control";
}

function protocolGroupName(item) {
  if (!selectedProtocolView) return null;
  if (selectedProtocolView.layer === "L4" && selectedProtocolView.protocol === "TCP") {
    return item.tcpPhaseGroup;
  }

  return selectedProtocolView.protocol;
}

function groupDescription(group, items) {
  if (selectedProtocolView?.layer === "L4" && selectedProtocolView.protocol === "TCP") {
    const payloadBytes = items.reduce((total, item) => total + (item.payload?.original_len ?? 0), 0);
    return `${items.length} packets, ${payloadBytes} payload bytes`;
  }

  return `${items.length} packets`;
}

function createGroupHeader(group, items) {
  const header = document.createElement("section");
  const collapsed = isGroupCollapsed(group);
  header.className = `event-group${collapsed ? " collapsed" : ""}`;
  header.innerHTML = `
    <button class="event-group-toggle" type="button">
      <span class="event-group-caret"></span>
      <span class="event-group-title"></span>
    </button>
    <div class="event-group-meta"></div>
  `;
  header.querySelector(".event-group-toggle").addEventListener("click", () => toggleGroup(group));
  header.querySelector(".event-group-caret").textContent = collapsed ? ">" : "v";
  header.querySelector(".event-group-title").textContent = group;
  header.querySelector(".event-group-meta").textContent = groupDescription(group, items);
  return header;
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

function createEventRow(item) {
  const row = document.createElement("article");
  row.className = "event";
  row.dataset.linkKey = item.linkKey || "";
  row.dataset.timestamp = String(item.timestamp);
  row.innerHTML = `
    <div class="event-header">
      <span>#${item.sequence} ${new Date(item.timestamp).toLocaleTimeString()}</span>
      <span>${item.kind.type}</span>
    </div>
    <div class="event-main"></div>
    <div class="event-tags"></div>
    <div class="event-detail"></div>
  `;
  row.querySelector(".event-main").textContent = item.summary.title;
  const tags = row.querySelector(".event-tags");
  for (const badge of item.summary.badges ?? []) {
    const tag = document.createElement("span");
    tag.className = "event-tag";
    tag.textContent = badge;
    tags.append(tag);
  }
  row.querySelector(".event-detail").textContent = item.summary.detail;
  return row;
}

function createEventRenderItems(visible) {
  if (!selectedProtocolView) {
    return visible.map((item) => ({ type: "event", item }));
  }

  const groups = new Map();
  for (const item of visible) {
    const group = protocolGroupName(item);
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(item);
  }

  const orderedGroups =
    selectedProtocolView.layer === "L4" && selectedProtocolView.protocol === "TCP"
      ? ["Handshake", "Transfer", "Teardown", "Reset", "Control", "Other"]
      : [...groups.keys()];

  const renderItems = [];
  for (const group of orderedGroups) {
    const items = groups.get(group);
    if (!items?.length) continue;
    const collapsed = isGroupCollapsed(group);
    renderItems.push({ type: "group", group, items });
    if (collapsed) continue;

    for (const item of items) {
      renderItems.push({ type: "event", item });
    }
  }

  return renderItems;
}

function estimatedHeight(item) {
  return item.type === "group" ? ESTIMATED_GROUP_HEIGHT : ESTIMATED_EVENT_HEIGHT;
}

function cumulativeHeights(renderItems) {
  const offsets = [0];
  for (const item of renderItems) {
    offsets.push(offsets[offsets.length - 1] + estimatedHeight(item));
  }
  return offsets;
}

function firstOffsetIndex(offsets, value) {
  let low = 0;
  let high = offsets.length - 1;

  while (low < high) {
    const mid = Math.floor((low + high) / 2);
    if (offsets[mid] < value) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }

  return low;
}

function createRenderNode(renderItem) {
  if (renderItem.type === "group") {
    return createGroupHeader(renderItem.group, renderItem.items);
  }

  return createEventRow(renderItem.item);
}

function createSpacer(height) {
  const spacer = document.createElement("div");
  spacer.className = "event-spacer";
  spacer.style.height = `${Math.max(0, height)}px`;
  return spacer;
}

function renderVirtualWindow() {
  if (!currentVirtualState) return;

  const { renderItems, offsets } = currentVirtualState;
  const viewportTop = Math.max(0, events.scrollTop - VIRTUAL_OVERSCAN_PX);
  const viewportBottom = events.scrollTop + events.clientHeight + VIRTUAL_OVERSCAN_PX;
  const startIndex = Math.max(0, firstOffsetIndex(offsets, viewportTop) - 1);
  const endIndex = Math.min(renderItems.length, firstOffsetIndex(offsets, viewportBottom) + 1);
  const fragment = document.createDocumentFragment();

  fragment.append(createSpacer(offsets[startIndex]));
  for (let index = startIndex; index < endIndex; index += 1) {
    fragment.append(createRenderNode(renderItems[index]));
  }
  fragment.append(createSpacer(offsets[offsets.length - 1] - offsets[endIndex]));

  events.replaceChildren(fragment);
}

function renderFullEvents(renderItems) {
  const fragment = document.createDocumentFragment();
  for (const item of renderItems) {
    fragment.append(createRenderNode(item));
  }
  events.replaceChildren(fragment);
}

function renderEvents() {
  const previousScrollTop = events.scrollTop;
  const visible = capturedEvents
    .filter(eventVisible)
    .sort((left, right) => left.timestamp - right.timestamp || left.sequence - right.sequence);
  const renderItems = createEventRenderItems(visible);

  if (renderItems.length < VIRTUAL_EVENT_THRESHOLD) {
    currentVirtualState = null;
    events.classList.remove("virtual-events");
    renderFullEvents(renderItems);
    events.scrollTop = previousScrollTop;
    return;
  }

  events.classList.add("virtual-events");
  currentVirtualState = {
    renderItems,
    offsets: cumulativeHeights(renderItems),
  };
  events.scrollTop = previousScrollTop;
  renderVirtualWindow();
}

function scheduleRender({
  links: shouldRenderLinks = false,
  events: shouldRenderEvents = false,
} = {}) {
  needsLinkRender ||= shouldRenderLinks;
  needsEventRender ||= shouldRenderEvents;
  if (renderScheduled) return;

  renderScheduled = true;
  requestAnimationFrame(() => {
    renderScheduled = false;

    if (needsLinkRender) {
      needsLinkRender = false;
      renderLinks();
    }

    if (needsEventRender) {
      needsEventRender = false;
      renderEvents();
    }
  });
}

function appendEvent(event) {
  eventCount += 1;
  const kind = eventKind(event);
  const summary = summarizeEvent(event);
  const flow = kind.type === "interface_packet" ? kind.flow : null;
  const protocols = linkProtocols(kind.packet);
  const rowLinkKey = flow ? updateLink(flow, kind.tcp, kind.payload, protocols) : "";
  capturedEvents.push({
    raw: event,
    kind,
    summary,
    linkKey: rowLinkKey || "",
    timestamp: timestampMillis(event.timestamp),
    sequence: eventCount,
    packet: kind.packet,
    protocols,
    tcp: kind.tcp,
    payload: kind.payload,
    tcpPhaseGroup: tcpPhaseGroup(kind.tcp, kind.payload),
  });
  scheduleRender({
    links: Boolean(rowLinkKey),
    events: eventVisible(capturedEvents[capturedEvents.length - 1]),
  });
}

function clearEvents() {
  eventCount = 0;
  selectedLinkKey = null;
  selectedProtocolView = null;
  linkStates.clear();
  capturedEvents.length = 0;
  collapsedGroups.clear();
  renderScheduled = false;
  needsLinkRender = false;
  needsEventRender = false;
  virtualScrollScheduled = false;
  currentVirtualState = null;
  events.classList.remove("virtual-events");
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
events.addEventListener("scroll", () => {
  if (!currentVirtualState || virtualScrollScheduled) return;

  virtualScrollScheduled = true;
  requestAnimationFrame(() => {
    virtualScrollScheduled = false;
    renderVirtualWindow();
  });
});

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
