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
const statusText = document.querySelector("#status");
const events = document.querySelector("#events");

let eventCount = 0;

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
  const row = document.createElement("article");
  row.className = "event";
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
  events.replaceChildren();
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
