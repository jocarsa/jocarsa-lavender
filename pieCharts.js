/********************************************
 * pieCharts.js
 ********************************************/

document.addEventListener("DOMContentLoaded", function() {
  const table = document.getElementById("submissionsTable");
  if (!table) return;

  const tbody = table.querySelector("tbody");
  if (!tbody) return;

  // We'll create ONE tooltip element for all charts:
  const chartTooltip = document.createElement("div");
  chartTooltip.id = "chartTooltip";
  chartTooltip.style.position = "absolute";
  chartTooltip.style.padding = "5px 10px";
  chartTooltip.style.background = "rgba(0,0,0,0.8)";
  chartTooltip.style.color = "#fff";
  chartTooltip.style.borderRadius = "4px";
  chartTooltip.style.fontSize = "12px";
  chartTooltip.style.pointerEvents = "none";
  chartTooltip.style.zIndex = "9999";
  chartTooltip.style.display = "none"; // hidden by default
  document.body.appendChild(chartTooltip);

  // Gather rows
  const rows = Array.from(tbody.getElementsByTagName("tr"));
  if (rows.length === 0) return;

  const thead = table.querySelector("thead");
  const headerRows = Array.from(thead.getElementsByTagName("tr"));
  // The row with piechart-container + inputs is typically headerRows[0]
  const filterRow = headerRows[0];
  const filterCells = Array.from(filterRow.getElementsByTagName("th"));

  // For each cell in the filter row that has .piechart-container
  filterCells.forEach((th, colIndex) => {
    const pieContainer = th.querySelector(".piechart-container");
    if (!pieContainer) return;

    // Ensure the container is position: relative
    pieContainer.style.position = "relative";

    // Gather text content from each row in this column
    let values = rows.map((r) => {
      const cells = r.getElementsByTagName("td");
      if (cells[colIndex]) {
        return cells[colIndex].innerText.trim();
      }
      return "";
    });

    // Build frequency map
    let freqMap = {};
    values.forEach((val) => {
      if (!val) return; // ignore blank
      freqMap[val] = (freqMap[val] || 0) + 1;
    });

    const distinctVals = Object.keys(freqMap);
    const numRows = rows.length;

    // Skip chart if:
    // 1) fewer than 2 distinct values, or
    // 2) all distinct => distinctVals.length == numRows (no repetition)
    if (distinctVals.length < 2 || distinctVals.length === numRows) {
      return;
    }

    // Build <svg> for the pie
    const svgSize = 80;
    const radius = 40;
    const cx = svgSize / 2;
    const cy = svgSize / 2;
    const total = distinctVals.reduce((acc, v) => acc + freqMap[v], 0);
    let currentAngle = 0;

    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", svgSize);
    svg.setAttribute("height", svgSize);
    svg.style.cursor = "pointer";
    svg.style.display = "block";  // so it flows in the container

    // We'll store references to each slice so we can highlight/unhighlight
    const slices = [];

    // A color palette
    const colors = [
      "#F44336","#E91E63","#9C27B0","#673AB7","#3F51B5","#2196F3","#03A9F4","#00BCD4",
      "#009688","#4CAF50","#8BC34A","#CDDC39","#FFEB3B","#FFC107","#FF9800","#FF5722"
    ];
    let colorIndex = 0;

    distinctVals.forEach((val) => {
      const sliceAngle = (freqMap[val] / total) * 2 * Math.PI;
      const x1 = cx + radius * Math.cos(currentAngle);
      const y1 = cy + radius * Math.sin(currentAngle);
      const x2 = cx + radius * Math.cos(currentAngle + sliceAngle);
      const y2 = cy + radius * Math.sin(currentAngle + sliceAngle);
      const largeArc = sliceAngle > Math.PI ? 1 : 0;

      const pathData = [
        `M ${cx},${cy}`,
        `L ${x1},${y1}`,
        `A ${radius},${radius} 0 ${largeArc} 1 ${x2},${y2}`,
        "Z",
      ].join(" ");

      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", pathData);
      path.setAttribute("fill", colors[colorIndex % colors.length]);
      path.style.transition = "opacity 0.2s"; // for fade
      colorIndex++;

      // Hover => show tooltip near the cursor
      path.addEventListener("mousemove", (e) => {
        chartTooltip.textContent = `${val} (${freqMap[val]})`;
        chartTooltip.style.left = e.pageX + 10 + "px";
        chartTooltip.style.top = e.pageY + 10 + "px";
        chartTooltip.style.display = "block";
      });
      path.addEventListener("mouseleave", () => {
        chartTooltip.style.display = "none";
      });

      // Click => filter
      path.addEventListener("click", () => {
        const filterInput = th.querySelector("input");
        if (!filterInput) return;
        filterInput.value = val;
        // highlight this slice, fade others
        slices.forEach((s) => {
          if (s === path) {
            // highlight
            s.style.stroke = "#000";
            s.style.strokeWidth = "2px";
            s.style.opacity = "1";
          } else {
            // fade
            s.style.stroke = "none";
            s.style.opacity = "0.3";
          }
        });
        // show the reset button
        resetBtn.style.display = "inline-block";
        // call existing filter function
        if (typeof filterTable === "function") {
          filterTable();
        }
      });

      svg.appendChild(path);
      slices.push(path);
      currentAngle += sliceAngle;
    });

    // Create a circular "Reset" button
    const resetBtn = document.createElement("button");
    resetBtn.classList.add("botonreset")
    /*
    resetBtn.textContent = "R";
    resetBtn.style.position = "absolute";
    resetBtn.style.top = "50%";
    resetBtn.style.left = "50%";
    resetBtn.style.transform = "translate(-50%, -50%)";
    resetBtn.style.width = "28px";
    resetBtn.style.height = "28px";
    resetBtn.style.borderRadius = "50%";
    resetBtn.style.border = "none";
    resetBtn.style.background = "#7E57C2";
    resetBtn.style.color = "#fff";
    resetBtn.style.fontWeight = "bold";
    resetBtn.style.fontSize = "14px";
    resetBtn.style.cursor = "pointer";
    resetBtn.style.display = "none"; // hidden until slice is clicked
    resetBtn.style.zIndex = "10";
    */

    // On "Reset" click => clear filter, un-fade slices, hide button
    resetBtn.addEventListener("click", () => {
      const filterInput = th.querySelector("input");
      if (filterInput) {
        filterInput.value = "";
      }
      slices.forEach((path) => {
        path.style.opacity = "1";
        path.style.stroke = "none";
      });
      resetBtn.style.display = "none";
      if (typeof filterTable === "function") {
        filterTable();
      }
    });

    // Append the svg & reset button to the container
    pieContainer.appendChild(svg);
    pieContainer.appendChild(resetBtn);
  });
});

