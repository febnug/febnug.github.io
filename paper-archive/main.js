const grid = document.querySelector("#paper-grid");

function statusClass(status) {
  return String(status || "").toLowerCase();
}

grid.innerHTML = papers.map((paper) => {
  const tags = paper.tags.map(tag => `<span class="badge">${tag}</span>`).join("");
  return `
    <article class="card">
      <div class="meta">
        <span class="badge ${statusClass(paper.status)}">${paper.status}</span>
        <span class="badge">${paper.year}</span>
        ${tags}
      </div>

      <h3>${paper.title}</h3>
      <p class="desc">${paper.description}</p>

      <div class="links">
        <a class="button primary" href="${paper.paperUrl}">read draft</a>
        <a class="button" href="${paper.pocUrl}">PoC</a>
      </div>
    </article>
  `;
}).join("");
