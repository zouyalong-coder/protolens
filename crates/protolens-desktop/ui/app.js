const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const targetInput = document.querySelector("#targetInput");
const diagnoseTargetButton = document.querySelector("#diagnoseTargetButton");
const targetDiagnosis = document.querySelector("#targetDiagnosis");
const interfaceSelect = document.querySelector("#interfaceSelect");
const filterInput = document.querySelector("#filterInput");
const payloadLimitInput = document.querySelector("#payloadLimitInput");
const countInput = document.querySelector("#countInput");
const pcapLoadInput = document.querySelector("#pcapLoadInput");
const tlsKeyLogInput = document.querySelector("#tlsKeyLogInput");
const startButton = document.querySelector("#startButton");
const stopButton = document.querySelector("#stopButton");
const savePcapPathButton = document.querySelector("#savePcapPathButton");
const loadPcapPathButton = document.querySelector("#loadPcapPathButton");
const tlsKeyLogPathButton = document.querySelector("#tlsKeyLogPathButton");
const launchChromeButton = document.querySelector("#launchChromeButton");
const loadPcapButton = document.querySelector("#loadPcapButton");
const refreshButton = document.querySelector("#refreshButton");
const clearButton = document.querySelector("#clearButton");
const timelineButton = document.querySelector("#timelineButton");
const timelineModal = document.querySelector("#timelineModal");
const timelineCloseButton = document.querySelector("#timelineCloseButton");
const timelineTitle = document.querySelector("#timelineTitle");
const timelineMeta = document.querySelector("#timelineMeta");
const timelineChart = document.querySelector("#timelineChart");
const timelinePacketList = document.querySelector("#timelinePacketList");
const timelinePacketDetail = document.querySelector("#timelinePacketDetail");
const linkSelect = document.querySelector("#linkSelect");
const linkCount = document.querySelector("#linkCount");
const linkFilterInput = document.querySelector("#linkFilterInput");
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
let timelineItems = [];
let timelineLaneIndexes = new Map();
let selectedTimelineSequence = null;
let knownInterfaces = [];
let lastTargetDiagnosis = null;
let noPacketTimer = null;
let captureStartEventCount = 0;
let captureStartSupportedPackets = 0;
let captureStartUnsupportedPackets = 0;
let supportedPacketCount = 0;
let unsupportedPacketCount = 0;
let lastSuggestedFilter = null;
let filterEditedByUser = false;

const VIRTUAL_EVENT_THRESHOLD = 1_200;
const VIRTUAL_OVERSCAN_PX = 900;
const ESTIMATED_EVENT_HEIGHT = 122;
const ESTIMATED_GROUP_HEIGHT = 42;
const MAX_TIMELINE_PACKETS = 300;
const TIMELINE_LANE_GAP = 104;
const TIMELINE_TOP = 72;
const TIMELINE_ROW_HEIGHT = 36;
const TIMELINE_PHASE_HEIGHT = 34;

function setRunning(running) {
  startButton.disabled = running;
  stopButton.disabled = !running;
  diagnoseTargetButton.disabled = running;
  savePcapPathButton.disabled = running;
  loadPcapPathButton.disabled = running;
  tlsKeyLogPathButton.disabled = running;
  launchChromeButton.disabled = running;
  loadPcapButton.disabled = running;
}

function setStatus(message) {
  statusText.textContent = message;
}

function setTargetDiagnosis(message) {
  targetDiagnosis.hidden = !message;
  targetDiagnosis.textContent = message || "";
}

function interfaceKind(item) {
  const name = item.name.toLowerCase();
  const description = (item.description || "").toLowerCase();
  if (name.startsWith("utun") || name.includes("tun")) return "VPN/tunnel";
  if (name === "lo0" || item.flags?.is_loopback) return "loopback";
  if (item.flags?.is_wireless || name.startsWith("en") || description.includes("wi-fi")) return "network";
  return "interface";
}

function renderInterfaceOptions(recommendedInterface = null) {
  const selected = recommendedInterface || interfaceSelect.value;
  interfaceSelect.replaceChildren();

  const sorted = [...knownInterfaces].sort((left, right) => {
    if (left.name === recommendedInterface) return -1;
    if (right.name === recommendedInterface) return 1;
    return left.name.localeCompare(right.name);
  });

  for (const item of sorted) {
    const option = document.createElement("option");
    const kind = interfaceKind(item);
    const recommended = item.name === recommendedInterface ? "recommended, " : "";
    option.value = item.name;
    option.textContent = item.description
      ? `${item.name} - ${recommended}${kind}, ${item.description}`
      : `${item.name} - ${recommended}${kind}`;
    interfaceSelect.append(option);
  }

  if (selected && [...interfaceSelect.options].some((option) => option.value === selected)) {
    interfaceSelect.value = selected;
  }
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

function packetLabel(tcp, payload, packet) {
  const transport = normalizeType(packet?.transport?.protocol || "");
  if (!tcp) return transport === "udp" ? "UDP datagram" : "Packet";
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

function escapeSvgText(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
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

function detailValue(value) {
  if (value === null || value === undefined || value === "") return "unknown";
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}

function appendDetailRow(list, label, value) {
  const term = document.createElement("dt");
  const description = document.createElement("dd");
  term.textContent = label;
  description.textContent = detailValue(value);
  list.append(term, description);
}

function createLayerSection(title, subtitle, rows) {
  const section = document.createElement("section");
  section.className = "packet-layer-section collapsed";

  const header = document.createElement("button");
  header.type = "button";
  header.className = "packet-layer-header";
  header.setAttribute("aria-expanded", "false");

  const titleElement = document.createElement("span");
  titleElement.className = "packet-layer-title";
  titleElement.textContent = title;
  const caret = document.createElement("span");
  caret.className = "packet-layer-caret";
  caret.textContent = ">";
  titleElement.prepend(caret);
  header.append(titleElement);

  if (subtitle) {
    const subtitleElement = document.createElement("span");
    subtitleElement.className = "packet-layer-subtitle";
    subtitleElement.textContent = subtitle;
    header.append(subtitleElement);
  }

  const list = document.createElement("dl");
  list.className = "packet-layer-grid";
  for (const [label, value] of rows) {
    appendDetailRow(list, label, value);
  }

  const body = document.createElement("div");
  body.className = "packet-layer-body";
  body.hidden = true;
  body.append(list);

  header.addEventListener("click", () => {
    const collapsed = section.classList.toggle("collapsed");
    body.hidden = collapsed;
    header.setAttribute("aria-expanded", String(!collapsed));
    caret.textContent = collapsed ? ">" : "v";
  });

  section.append(header, body);
  return section;
}

function createPayloadSection(payload) {
  const payloadPreview = payload?.preview || "No UTF-8 preview";
  const payloadSection = createLayerSection("Payload", payload ? `${payload.original_len} B` : "0 B", [
    ["Original Length", payload ? `${payload.original_len} B` : "0 B"],
    ["Encoding", payload?.encoding],
    ["Truncated", payload?.truncated ?? false],
    ["UTF-8 Preview", payloadPreview],
  ]);
  const dataBlock = document.createElement("pre");
  dataBlock.className = "packet-payload-data";
  dataBlock.textContent = payload?.data || "No payload bytes captured";
  payloadSection.querySelector(".packet-layer-body").append(dataBlock);
  return payloadSection;
}

function renderLayerSections(container, item, flags) {
  container.replaceChildren();

  if (!item.packet) {
    const empty = document.createElement("div");
    empty.className = "timeline-empty compact";
    empty.textContent = "No parsed layer metadata";
    container.append(empty, createPayloadSection(item.payload));
    return;
  }

  const packet = item.packet;
  const flow = item.kind.flow;
  const payload = item.payload;

  container.append(
    createLayerSection("L2 Link", protocolName(packet.link.medium), [
      ["Medium", packet.link.medium],
      ["Encapsulated Protocol", packet.link.protocol],
      ["Header Length", `${packet.link.header_len} B`],
      ["Frame Length", `${packet.link.frame_len} B`],
    ]),
    createLayerSection("L3 Network", protocolName(packet.network.protocol), [
      ["Protocol", packet.network.protocol],
      ["Header Length", `${packet.network.header_len} B`],
      ["Packet Length", `${packet.network.packet_len} B`],
      ["TTL / Hop Limit", packet.network.hop_limit],
    ]),
    createLayerSection("L4 Transport", protocolName(packet.transport.protocol), [
      ["Protocol", protocolName(packet.transport.protocol)],
      ["Source", flow ? endpoint(flow.source) : null],
      ["Destination", flow ? endpoint(flow.destination) : null],
      ["Header Length", `${packet.transport.header_len} B`],
      ["Segment Length", `${packet.transport.segment_len} B`],
      ["TCP Flags", flags],
    ]),
  );

  container.append(createPayloadSection(payload));
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

function linkTitle(link) {
  return link.client && link.server ? `${link.client} -> ${link.server}` : `${link.left} <-> ${link.right}`;
}

function linkFilterTerms() {
  return linkFilterInput.value
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

function linkSearchText(link) {
  const protocols = protocolItems(link).map((item) => `${item.layer} ${item.protocol}`);
  return [
    linkTitle(link),
    link.left,
    link.right,
    link.client,
    link.server,
    link.phase,
    `${link.packets} packets`,
    `${link.bytes} bytes`,
    ...protocols,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function linkMatchesFilter(link, terms) {
  if (!terms.length) return true;
  const searchText = linkSearchText(link);
  return terms.every((term) => searchText.includes(term));
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
  const filterTerms = linkFilterTerms();
  const visibleLinks = sorted.filter((link) => linkMatchesFilter(link, filterTerms));
  const previousValue = linkSelect.value;
  const optionFragment = document.createDocumentFragment();
  const linkFragment = document.createDocumentFragment();
  optionFragment.append(new Option("All links", ""));
  linkCount.textContent = filterTerms.length ? `${visibleLinks.length}/${sorted.length}` : String(sorted.length);

  for (const link of visibleLinks) {
    const title = linkTitle(link);
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

  if (!visibleLinks.length) {
    const empty = document.createElement("div");
    empty.className = "links-empty";
    empty.textContent = sorted.length ? "No links match this filter" : "No links captured";
    linkFragment.append(empty);
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
    const label = packetLabel(kind.tcp, payload, kind.packet);
    const flowDisplay = flow ? orderedFlow(flow) : null;
    const title = flowDisplay ? `${label}: ${flowDisplay.left} ${flowDisplay.arrow} ${flowDisplay.right}` : label;
    const preview = payload?.preview ? ` preview=${JSON.stringify(payload.preview)}` : "";
    return {
      title,
      detail: `${layerDetail(kind.packet)} | flags=${flags} | ${payloadLabel(payload)}${preview}`,
      badges: [label, payloadLabel(payload), flags],
    };
  }

  if (kind.type === "unsupported_packet") {
    return {
      title: `Unsupported packet: ${kind.link_type || "unknown link"}`,
      detail: `${kind.reason || "not parsed"} | frame=${kind.frame_len ?? 0}B`,
      badges: ["Unsupported", kind.link_type || "unknown"],
    };
  }

  if (kind.type === "protocol_observation") {
    const payload = kind.metadata?.payload;
    const preview = payload?.preview ? ` preview=${JSON.stringify(payload.preview)}` : "";
    return {
      title: kind.summary || kind.analyzer_id || "Protocol observation",
      detail: payload
        ? `${kind.analyzer_id || "analyzer"} | ${payloadLabel(payload)}${preview}`
        : JSON.stringify(kind.metadata ?? {}),
      badges: [kind.analyzer_id || "Observation", payload ? payloadLabel(payload) : "metadata"],
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
  if (kind.type === "interface_packet") supportedPacketCount += 1;
  if (kind.type === "unsupported_packet") unsupportedPacketCount += 1;
  const summary = summarizeEvent(event);
  const flow = kind.type === "interface_packet" ? kind.flow : kind.metadata?.flow ?? null;
  const protocols = linkProtocols(kind.packet);
  const observationPayload = kind.type === "protocol_observation" ? kind.metadata?.payload : null;
  const rowLinkKey =
    flow && kind.type === "interface_packet"
      ? updateLink(flow, kind.tcp, kind.payload, protocols)
      : linkKey(flow);
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
    payload: kind.payload || observationPayload,
    tcpPhaseGroup: tcpPhaseGroup(kind.tcp, kind.payload || observationPayload),
  });
  scheduleRender({
    links: Boolean(rowLinkKey),
    events: eventVisible(capturedEvents[capturedEvents.length - 1]),
  });
}

function clearEvents() {
  eventCount = 0;
  supportedPacketCount = 0;
  unsupportedPacketCount = 0;
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
  linkFilterInput.value = "";
}

function timelinePackets() {
  return capturedEvents
    .filter(eventVisible)
    .filter((item) => item.kind.type === "interface_packet" && item.kind.flow)
    .sort((left, right) => left.timestamp - right.timestamp || left.sequence - right.sequence);
}

function timelineContextLabel() {
  if (selectedProtocolView) {
    return `${selectedProtocolView.layer} ${selectedProtocolView.protocol}`;
  }

  if (selectedLinkKey) {
    return selectedLinkKey.replace("<->", " <-> ");
  }

  return "All visible packets";
}

function packetTimelineLabel(item) {
  const transport = item.protocols.find((protocol) => protocol.layer === "L4")?.protocol ?? "PACKET";
  const base = item.tcp ? packetLabel(item.tcp, item.payload, item.packet) : transport;
  const payload = item.payload?.original_len ? ` ${item.payload.original_len}B` : "";
  return `${base}${payload}`;
}

function timelineLaneKey(endpointValue) {
  return endpoint(endpointValue);
}

function timelineDirection(item) {
  const source = endpoint(item.kind.flow.source);
  const destination = endpoint(item.kind.flow.destination);
  const sourceIndex = timelineLaneIndexes.get(source) ?? 0;
  const destinationIndex = timelineLaneIndexes.get(destination) ?? sourceIndex;
  if (sourceIndex <= destinationIndex) {
    return {
      left: source,
      right: destination,
      arrow: "->",
    };
  }

  return {
    left: destination,
    right: source,
    arrow: "<-",
  };
}

function timelineDirectionLabel(item) {
  const direction = timelineDirection(item);
  return `${direction.left} ${direction.arrow} ${direction.right}`;
}

function selectedTimelineItem(sequence) {
  return timelineItems.find((item) => item.sequence === sequence) ?? null;
}

function renderTimelineDetail(item) {
  timelinePacketDetail.replaceChildren();

  if (!item) {
    timelinePacketDetail.innerHTML = `<div class="timeline-empty compact">Select a packet</div>`;
    return;
  }

  const flags = item.tcp ? tcpFlags(item.tcp) : "none";
  const preview = item.payload?.preview ?? "";
  const rawJson = JSON.stringify(item.raw, null, 2);

  const detail = document.createElement("div");
  detail.className = "timeline-detail-content";
  detail.innerHTML = `
    <div class="timeline-detail-heading">
      <div>
        <p class="timeline-detail-kicker"></p>
        <h3 class="timeline-detail-title"></h3>
      </div>
      <button class="raw-event-button" type="button">Raw</button>
      <div class="raw-event-popover" hidden>
        <pre class="detail-raw"></pre>
      </div>
    </div>
    <dl class="timeline-detail-grid">
      <dt>Direction</dt>
      <dd class="detail-direction"></dd>
      <dt>Time</dt>
      <dd class="detail-time"></dd>
      <dt>Phase</dt>
      <dd class="detail-phase"></dd>
      <dt>Flags</dt>
      <dd class="detail-flags"></dd>
      <dt>Payload</dt>
      <dd class="detail-payload"></dd>
    </dl>
    <div class="timeline-detail-section">
      <p class="timeline-detail-section-title">Layers</p>
      <div class="detail-layers packet-layer-list"></div>
    </div>
    <div class="timeline-detail-section">
      <p class="timeline-detail-section-title">Preview</p>
      <pre class="detail-preview"></pre>
    </div>
  `;

  detail.querySelector(".timeline-detail-kicker").textContent = `Packet #${item.sequence}`;
  detail.querySelector(".timeline-detail-title").textContent = packetTimelineLabel(item);
  detail.querySelector(".detail-direction").textContent = timelineDirectionLabel(item);
  detail.querySelector(".detail-time").textContent = new Date(item.timestamp).toLocaleString();
  detail.querySelector(".detail-phase").textContent = item.tcpPhaseGroup ?? "Other";
  detail.querySelector(".detail-flags").textContent = flags;
  detail.querySelector(".detail-payload").textContent = payloadLabel(item.payload);
  renderLayerSections(detail.querySelector(".detail-layers"), item, flags);
  detail.querySelector(".detail-preview").textContent = preview || "No UTF-8 preview";
  detail.querySelector(".detail-raw").textContent = rawJson;
  const rawButton = detail.querySelector(".raw-event-button");
  const rawPopover = detail.querySelector(".raw-event-popover");
  rawButton.addEventListener("click", () => {
    rawPopover.hidden = !rawPopover.hidden;
  });
  timelinePacketDetail.append(detail);
}

function selectTimelinePacket(sequence) {
  selectedTimelineSequence = sequence;

  for (const element of timelineChart.querySelectorAll(".timeline-packet")) {
    element.classList.toggle("selected", Number(element.dataset.sequence) === sequence);
  }

  for (const element of timelinePacketList.querySelectorAll(".timeline-packet-item")) {
    const selected = Number(element.dataset.sequence) === sequence;
    element.classList.toggle("selected", selected);
    if (selected) {
      timelinePacketList.scrollTo({
        top: element.offsetTop - timelinePacketList.clientHeight / 2 + element.clientHeight / 2,
        behavior: "auto",
      });
    }
  }

  renderTimelineDetail(selectedTimelineItem(sequence));
}

function renderTimelinePacketList(items) {
  const fragment = document.createDocumentFragment();

  for (const item of items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "timeline-packet-item";
    button.dataset.sequence = String(item.sequence);
    button.innerHTML = `
      <span class="timeline-packet-item-title"></span>
      <span class="timeline-packet-item-meta"></span>
    `;
    button.querySelector(".timeline-packet-item-title").textContent = packetTimelineLabel(item);
    button.querySelector(".timeline-packet-item-meta").textContent =
      `#${item.sequence} ${timelineDirectionLabel(item)}`;
    button.addEventListener("click", () => selectTimelinePacket(item.sequence));
    fragment.append(button);
  }

  timelinePacketList.replaceChildren(fragment);
}

function timelineHasTcpPhases(items) {
  return items.some((item) => item.protocols.some((protocol) => protocol.layer === "L4" && protocol.protocol === "TCP"));
}

function createTimelineRows(items) {
  if (!timelineHasTcpPhases(items)) {
    return items.map((item) => ({ type: "packet", item }));
  }

  const phaseOrder = ["Handshake", "Transfer", "Teardown", "Reset", "Other"];
  const groups = new Map();
  let currentPhase = "Handshake";
  for (const item of items) {
    let phase = item.tcpPhaseGroup ?? "Other";
    if (phase === "Control") {
      phase = currentPhase;
    } else if (phase !== "Other") {
      currentPhase = phase;
    }

    if (!groups.has(phase)) groups.set(phase, []);
    groups.get(phase).push(item);
  }

  const rows = [];
  for (const phase of phaseOrder) {
    const phaseItems = groups.get(phase);
    if (!phaseItems?.length) continue;
    rows.push({ type: "phase", phase, items: phaseItems });
    for (const item of phaseItems) {
      rows.push({ type: "packet", item });
    }
  }

  return rows;
}

function renderTimelineChart(items) {
  timelineTitle.textContent = timelineContextLabel();
  timelineChart.replaceChildren();
  timelinePacketList.replaceChildren();
  timelinePacketDetail.replaceChildren();
  selectedTimelineSequence = null;

  if (!items.length) {
    timelineMeta.textContent = "No packets in the current view.";
    timelineChart.innerHTML = `<div class="timeline-empty">No packet flow to draw.</div>`;
    timelinePacketList.innerHTML = `<div class="timeline-empty compact">No packets</div>`;
    timelinePacketDetail.innerHTML = `<div class="timeline-empty compact">No packet selected</div>`;
    return;
  }

  const shown = items.slice(0, MAX_TIMELINE_PACKETS);
  const timelineRows = createTimelineRows(shown);
  timelineItems = shown;
  const lanes = [];
  const laneIndexes = new Map();
  for (const item of shown) {
    for (const value of [item.kind.flow.source, item.kind.flow.destination]) {
      const key = timelineLaneKey(value);
      if (!laneIndexes.has(key)) {
        laneIndexes.set(key, lanes.length);
        lanes.push(key);
      }
    }
  }
  timelineLaneIndexes = laneIndexes;

  const width = Math.max(320, 72 + Math.max(1, lanes.length - 1) * TIMELINE_LANE_GAP + 86);
  const height =
    TIMELINE_TOP +
    timelineRows.reduce(
      (total, row) => total + (row.type === "phase" ? TIMELINE_PHASE_HEIGHT : TIMELINE_ROW_HEIGHT),
      0,
    ) +
    54;
  const firstTimestamp = shown[0].timestamp;
  const lastTimestamp = shown[shown.length - 1].timestamp;
  const duration = Math.max(0, lastTimestamp - firstTimestamp);
  const laneX = (lane) => 58 + lane * TIMELINE_LANE_GAP;
  const labelY = 28;
  let svg = `<svg class="timeline-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Packet timeline">`;

  svg += `<defs><marker id="timelineArrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" /></marker></defs>`;

  lanes.forEach((lane, index) => {
    const x = laneX(index);
    svg += `<line class="timeline-lane" x1="${x}" y1="46" x2="${x}" y2="${height - 24}" />`;
    svg += `<text class="timeline-lane-label" x="${x}" y="${labelY}" text-anchor="middle">${escapeSvgText(lane)}</text>`;
  });

  let currentY = TIMELINE_TOP;
  timelineRows.forEach((row) => {
    if (row.type === "phase") {
      const count = row.items.length;
      const payloadBytes = row.items.reduce((total, item) => total + (item.payload?.original_len ?? 0), 0);
      svg += `<rect class="timeline-phase-band" x="0" y="${currentY - 19}" width="${width}" height="${TIMELINE_PHASE_HEIGHT}" />`;
      svg += `<text class="timeline-phase-title" x="12" y="${currentY + 3}">${escapeSvgText(row.phase)}</text>`;
      svg += `<text class="timeline-phase-meta" x="96" y="${currentY + 3}">${count} pkts / ${payloadBytes}B</text>`;
      currentY += TIMELINE_PHASE_HEIGHT;
      return;
    }

    const item = row.item;
    const sourceIndex = laneIndexes.get(timelineLaneKey(item.kind.flow.source));
    const destinationIndex = laneIndexes.get(timelineLaneKey(item.kind.flow.destination));
    const x1 = laneX(sourceIndex);
    const x2 = laneX(destinationIndex);
    const y = currentY;
    const labelX = x1 === x2 ? x1 + 16 : (x1 + x2) / 2;
    const labelAnchor = x1 === x2 ? "start" : "middle";
    const elapsed = item.timestamp - firstTimestamp;
    const label = packetTimelineLabel(item);

    svg += `<g class="timeline-packet" data-sequence="${item.sequence}" tabindex="0" role="button" aria-label="${escapeSvgText(label)}">`;
    svg += `<rect class="timeline-hit-area" x="0" y="${y - TIMELINE_ROW_HEIGHT / 2}" width="${width}" height="${TIMELINE_ROW_HEIGHT}" />`;
    svg += `<text class="timeline-time" x="12" y="${y + 4}">+${elapsed}ms</text>`;
    svg += `<line class="timeline-arrow timeline-hit-line" x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" />`;
    svg += `<line class="timeline-arrow" x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" marker-end="url(#timelineArrow)" />`;
    svg += `<circle class="timeline-point" cx="${x1}" cy="${y}" r="3" />`;
    svg += `<text class="timeline-packet-label" x="${labelX}" y="${y - 7}" text-anchor="${labelAnchor}">${escapeSvgText(label)}</text>`;
    svg += `</g>`;
    currentY += TIMELINE_ROW_HEIGHT;
  });

  svg += `</svg>`;
  timelineMeta.textContent =
    `Showing ${shown.length} of ${items.length} packets across ${lanes.length} endpoints over ${duration}ms.`;
  timelineChart.innerHTML = svg;
  renderTimelinePacketList(shown);
  timelineChart.querySelectorAll(".timeline-packet").forEach((element) => {
    element.addEventListener("click", () => selectTimelinePacket(Number(element.dataset.sequence)));
    element.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectTimelinePacket(Number(element.dataset.sequence));
      }
    });
  });
  selectTimelinePacket(shown[0].sequence);
}

function openTimeline() {
  renderTimelineChart(timelinePackets());
  timelineModal.hidden = false;
  timelineCloseButton.focus();
}

function closeTimeline() {
  timelineModal.hidden = true;
  timelineItems = [];
  timelineLaneIndexes = new Map();
  selectedTimelineSequence = null;
  timelinePacketDetail.replaceChildren();
}

async function loadInterfaces() {
  setStatus("Loading interfaces...");
  try {
    knownInterfaces = await invoke("list_interfaces");
    renderInterfaceOptions(lastTargetDiagnosis?.recommendedInterface || null);
    setStatus(knownInterfaces.length ? `Loaded ${knownInterfaces.length} interfaces` : "No interfaces found");
  } catch (error) {
    setStatus(`Failed to load interfaces: ${error}`);
  }
}

async function diagnoseTarget({ apply = true } = {}) {
  const target = targetInput.value.trim();
  if (!target) {
    setTargetDiagnosis("");
    lastTargetDiagnosis = null;
    return null;
  }

  setStatus("Detecting target route...");
  const diagnosis = await invoke("diagnose_target", { request: { target } });
  lastTargetDiagnosis = diagnosis;

  if (apply) {
    if (diagnosis.recommendedInterface) {
      renderInterfaceOptions(diagnosis.recommendedInterface);
      interfaceSelect.value = diagnosis.recommendedInterface;
    }
    const canApplyFilter =
      diagnosis.bpfFilter &&
      (!filterEditedByUser || !filterInput.value.trim() || filterInput.value === lastSuggestedFilter);
    if (canApplyFilter) {
      filterInput.value = diagnosis.bpfFilter;
      lastSuggestedFilter = diagnosis.bpfFilter;
      filterEditedByUser = false;
    }
  }

  const route = diagnosis.recommendedInterface ? `route ${diagnosis.recommendedInterface}` : "route unknown";
  const ip = diagnosis.selectedIp || diagnosis.resolvedIps?.[0] || "unresolved";
  const fakeIp = diagnosis.fakeIp ? "proxy fake IP, " : "";
  const filter = diagnosis.bpfFilter ? `filter ${diagnosis.bpfFilter}` : "no BPF suggestion";
  setTargetDiagnosis(`${diagnosis.host}:${diagnosis.port} -> ${ip}; ${fakeIp}${route}; ${filter}`);
  setStatus(diagnosis.recommendedInterface ? `Target route detected: ${diagnosis.recommendedInterface}` : "Target detected");

  return diagnosis;
}

async function startCapture() {
  const payloadLimit = Number.parseInt(payloadLimitInput.value, 10);
  const count = countInput.value ? Number.parseInt(countInput.value, 10) : null;

  setStatus("Starting capture...");
  try {
    if (targetInput.value.trim()) {
      await diagnoseTarget({ apply: false });
    }

    await invoke("start_capture", {
      request: {
        interface: interfaceSelect.value,
        filter: filterInput.value || "tcp or udp port 53",
        payloadLimit: Number.isFinite(payloadLimit) ? payloadLimit : 65535,
        count: Number.isFinite(count) ? count : null,
        tlsKeyLogPath: tlsKeyLogInput.value.trim() || null,
      },
    });
    setRunning(true);
    captureStartEventCount = eventCount;
    captureStartSupportedPackets = supportedPacketCount;
    captureStartUnsupportedPackets = unsupportedPacketCount;
    clearTimeout(noPacketTimer);
    noPacketTimer = setTimeout(() => {
      if (!stopButton.disabled && lastTargetDiagnosis) {
        const supportedDelta = supportedPacketCount - captureStartSupportedPackets;
        const unsupportedDelta = unsupportedPacketCount - captureStartUnsupportedPackets;
        if (supportedDelta > 0) return;

        const recommended = lastTargetDiagnosis.recommendedInterface;
        const current = interfaceSelect.value;
        let hint = "No raw packets arrived for this target filter; verify the interface, target IP, and BPF.";
        if (unsupportedDelta > 0) {
          hint = `${unsupportedDelta} raw packets arrived, but ProtoLens could not parse them yet. Check the unsupported packet rows for link type and reason.`;
        } else if (eventCount !== captureStartEventCount) {
          hint = "Only control or DNS events arrived; no target packet matched the current parser.";
        } else if (recommended && recommended !== current) {
          hint = `No raw packets yet. Target route uses ${recommended}; current interface is ${current}.`;
        }
        setTargetDiagnosis(`${targetDiagnosis.textContent} | ${hint}`);
      }
    }, 4000);
    setStatus("Capture running, recording PCAP to ~/.protolens/capture.pcap");
  } catch (error) {
    setStatus(`Failed to start: ${error}`);
  }
}

async function stopCapture() {
  await invoke("stop_capture");
  clearTimeout(noPacketTimer);
  setStatus("Stopping capture...");
}

async function chooseSavePcapPath() {
  try {
    const path = await invoke("save_current_pcap_as");
    if (path) {
      setStatus(`Saved PCAP to ${path}`);
    }
  } catch (error) {
    setStatus(`Failed to save PCAP: ${error}`);
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

async function chooseTlsKeyLogPath() {
  try {
    const path = await invoke("select_tls_key_log_path");
    if (path) {
      tlsKeyLogInput.value = path;
      setStatus(`Using TLS key log ${path}`);
    }
  } catch (error) {
    setStatus(`Failed to choose TLS key log: ${error}`);
  }
}

async function launchChromeWithTlsKeyLog() {
  const confirmed = window.confirm(
    "Please close any running Chrome windows before launching Chrome from ProtoLens. Continue?",
  );
  if (!confirmed) return;

  let path = tlsKeyLogInput.value.trim();
  try {
    if (!path) {
      path = await invoke("select_tls_key_log_path");
      if (!path) return;
      tlsKeyLogInput.value = path;
    }
    const message = await invoke("launch_chrome_with_tls_key_log", {
      request: { tlsKeyLogPath: path },
    });
    setStatus(message);
  } catch (error) {
    setStatus(`Failed to launch Chrome: ${error}`);
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
        payloadLimit: Number.isFinite(payloadLimit) ? payloadLimit : 65535,
        tlsKeyLogPath: tlsKeyLogInput.value.trim() || null,
      },
    });
    setStatus(`Loaded ${count} events from ${path}`);
  } catch (error) {
    setStatus(`Failed to load pcap: ${error}`);
  }
}

startButton.addEventListener("click", startCapture);
stopButton.addEventListener("click", stopCapture);
filterInput.addEventListener("input", () => {
  filterEditedByUser = filterInput.value !== lastSuggestedFilter;
});
diagnoseTargetButton.addEventListener("click", () => {
  diagnoseTarget().catch((error) => setStatus(`Failed to detect target: ${error}`));
});
savePcapPathButton.addEventListener("click", chooseSavePcapPath);
loadPcapPathButton.addEventListener("click", chooseLoadPcapPath);
tlsKeyLogPathButton.addEventListener("click", chooseTlsKeyLogPath);
launchChromeButton.addEventListener("click", launchChromeWithTlsKeyLog);
loadPcapButton.addEventListener("click", loadPcap);
refreshButton.addEventListener("click", loadInterfaces);
clearButton.addEventListener("click", clearEvents);
timelineButton.addEventListener("click", openTimeline);
timelineCloseButton.addEventListener("click", closeTimeline);
timelineModal.addEventListener("click", (event) => {
  if (event.target === timelineModal) closeTimeline();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !timelineModal.hidden) closeTimeline();
});
linkSelect.addEventListener("change", () => selectLink(linkSelect.value || null));
linkFilterInput.addEventListener("input", () => renderLinks());
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
  clearTimeout(noPacketTimer);
  setStatus(`Capture error: ${event.payload}`);
});
listen("capture-stopped", () => {
  setRunning(false);
  clearTimeout(noPacketTimer);
  setStatus("Capture stopped");
});

loadInterfaces();
