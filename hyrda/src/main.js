// const { invoke } = window.__TAURI__.core;

// let greetInputEl;
// let greetMsgEl;

// async function greet() {
//   // Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
//   greetMsgEl.textContent = await invoke("greet", { name: greetInputEl.value });
// }

// window.addEventListener("DOMContentLoaded", () => {
//   greetInputEl = document.querySelector("#greet-input");
//   greetMsgEl = document.querySelector("#greet-msg");
//   document.querySelector("#greet-form").addEventListener("submit", (e) => {
//     e.preventDefault();
//     greet();
//   });
// });
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

window.addEventListener("DOMContentLoaded", () => {
  const openBtn = document.getElementById("open-btn");
  const fileMeta = document.getElementById("file-meta");
  const segmentList = document.getElementById("segment-list");
  const chunkTable = document.getElementById("chunk-table");
  const chunkBody = document.getElementById("chunk-body");
  const statusText = document.getElementById("status-text");
  const outputConsole = document.getElementById("output-console");


  const sidebar = document.getElementById("ida-sidebar");
  const sidebarSplitter = document.getElementById("sidebar-splitter");
  const bottomDock = document.getElementById("ida-bottom-dock");
  const consoleSplitter = document.getElementById("console-splitter");

  let isDraggingSidebar = false;
  let isDraggingConsole = false;

  sidebarSplitter.addEventListener("mousedown", () => {
    isDraggingSidebar = true;
    sidebarSplitter.classList.add("dragging");
  });

  consoleSplitter.addEventListener("mousedown", () => {
    isDraggingConsole = true;
    consoleSplitter.classList.add("dragging");
  });

  window.addEventListener("mousemove", (e) => {
    if (isDraggingSidebar) {
      const newWidth = e.clientX;
      if (newWidth > 150 && newWidth < 600) {
        sidebar.style.width = `${newWidth}px`;
      }
    }

    if (isDraggingConsole) {
      const workspaceHeight = window.innerHeight;
      const newHeight = workspaceHeight - e.clientY - 25; // Account for status bar
      if (newHeight > 50 && newHeight < 500) {
        bottomDock.style.height = `${newHeight}px`;
      }
    }
  });

  window.addEventListener("mouseup", () => {
    isDraggingSidebar = false;
    isDraggingConsole = false;
    sidebarSplitter.classList.remove("dragging");
    consoleSplitter.classList.remove("dragging");
  });


  function logMessage(text, type = "info") {
    const p = document.createElement("p");
    p.className = `log-${type}`;
    p.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    outputConsole.appendChild(p);
    outputConsole.scrollTop = outputConsole.scrollHeight;
  }

  openBtn.addEventListener("click", async () => {
    try {
      const filePath = await open({ multiple: false, directory: false });
      if (!filePath) return;

      statusText.textContent = "IDB: Parsing binary structure...";
      fileMeta.textContent = "Loading...";
      chunkBody.innerHTML = "";
      segmentList.innerHTML = "";

      logMessage(`Opening target file: ${filePath}`, "info");

      const result = await invoke("decompose_binary", { path: filePath });

      fileMeta.innerHTML = `<span style="color:#ce9178">${result.file_name}</span> [${result.file_size} bytes]`;
      logMessage(`Successfully mapped ${result.file_size} bytes across ${result.chunks.length} preview chunks.`, "success");

      let rows = "";
      let sidebarHtml = "";

      result.chunks.forEach((chunk, index) => {
        const hexOffset = "0x" + chunk.offset.toString(16).toUpperCase().padStart(8, "0");

        rows += `
          <tr>
            <td class="addr-col">${hexOffset}</td>
            <td>${chunk.size}h</td>
            <td class="hex-dump">${chunk.hex_preview}</td>
          </tr>
        `;

        sidebarHtml += `<div class="nav-item" data-index="${index}">seg_00_${index.toString(16).padStart(2, '0')} (${hexOffset})</div>`;
      });

      chunkBody.innerHTML = rows;
      segmentList.innerHTML = sidebarHtml;
      chunkTable.classList.remove("hidden");

      statusText.textContent = "IDB: Analysis Completed Successfully";
      logMessage("Auto-analysis complete. Database synchronized.", "success");
    } catch (error) {
      statusText.textContent = "IDB: Error occurred";
      fileMeta.textContent = `Error: ${error}`;
      logMessage(`Fatal error during decomposition: ${error}`, "error");
    }
  });
});
