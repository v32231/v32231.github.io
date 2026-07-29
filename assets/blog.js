(function () {
  "use strict";

  var header = document.querySelector(".header");
  var nav = document.querySelector(".nav--header");
  var navButton = document.querySelector(".button--nav");

  function updateHeaderHeight() {
    if (!header) return;
    document.documentElement.style.setProperty("--header-height", header.offsetHeight + "px");
  }

  if (nav && navButton) {
    navButton.addEventListener("click", function () {
      var isOpen = nav.classList.toggle("is-open");
      navButton.setAttribute("aria-expanded", String(isOpen));
      navButton.setAttribute("aria-label", isOpen ? "메뉴 닫기" : "메뉴 열기");
      updateHeaderHeight();
    });

    nav.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        nav.classList.remove("is-open");
        navButton.setAttribute("aria-expanded", "false");
        navButton.setAttribute("aria-label", "메뉴 열기");
      });
    });
  }

  updateHeaderHeight();
  window.addEventListener("resize", updateHeaderHeight);

  if (window.ResizeObserver && header) {
    new ResizeObserver(updateHeaderHeight).observe(header);
  }

  var postLayout = document.querySelector(".post-layout");
  var postBody = document.querySelector(".post-body");
  var toc = document.querySelector(".post-toc");
  var tocList = document.querySelector("#post-toc-list");

  if (!postLayout || !postBody || !toc || !tocList) return;

  postBody.querySelectorAll("table").forEach(function (table) {
    if (table.parentElement.classList.contains("table-scroll")) return;

    var wrapper = document.createElement("div");
    wrapper.className = "table-scroll";
    wrapper.setAttribute("role", "region");
    wrapper.setAttribute("aria-label", "가로로 스크롤할 수 있는 표");
    wrapper.setAttribute("tabindex", "0");

    table.parentNode.insertBefore(wrapper, table);
    wrapper.appendChild(table);
  });

  var headings = Array.prototype.slice.call(postBody.querySelectorAll("h1, h2, h3, h4"));

  if (headings.length === 0) {
    toc.hidden = true;
    postLayout.classList.add("toc-empty");
  } else {
    var usedIds = {};

    headings.forEach(function (heading, index) {
      var baseId = heading.id || "section-" + (index + 1);
      var id = baseId;
      var suffix = 2;

      while (usedIds[id]) {
        id = baseId + "-" + suffix;
        suffix += 1;
      }

      usedIds[id] = true;
      heading.id = id;

      var item = document.createElement("li");
      item.className = "post-toc__item post-toc__item--" + heading.tagName.toLowerCase();

      var link = document.createElement("a");
      link.className = "post-toc__link";
      link.href = "#" + id;
      link.textContent = heading.textContent.trim();
      link.dataset.headingId = id;

      item.appendChild(link);
      tocList.appendChild(item);
    });
  }

  var tocLinks = Array.prototype.slice.call(tocList.querySelectorAll(".post-toc__link"));
  var ticking = false;

  function setActiveHeading(id) {
    tocLinks.forEach(function (link) {
      var active = link.dataset.headingId === id;
      link.classList.toggle("is-active", active);
      if (active) {
        link.setAttribute("aria-current", "location");
      } else {
        link.removeAttribute("aria-current");
      }
    });

    var activeLink = tocList.querySelector(".post-toc__link.is-active");
    if (!activeLink || toc.hidden) return;

    var tocRect = toc.getBoundingClientRect();
    var linkRect = activeLink.getBoundingClientRect();

    if (linkRect.top < tocRect.top || linkRect.bottom > tocRect.bottom) {
      toc.scrollTop += linkRect.top - tocRect.top - toc.clientHeight / 2;
    }
  }

  function updateScrollState() {
    var headerOffset = header ? header.offsetHeight + 36 : 108;
    var currentHeading = headings[0];

    headings.forEach(function (heading) {
      if (heading.getBoundingClientRect().top <= headerOffset) {
        currentHeading = heading;
      }
    });

    if (currentHeading) {
      setActiveHeading(currentHeading.id);
    }

    ticking = false;
  }

  function requestScrollUpdate() {
    if (ticking) return;
    ticking = true;
    window.requestAnimationFrame(updateScrollState);
  }

  window.addEventListener("scroll", requestScrollUpdate, { passive: true });
  window.addEventListener("resize", requestScrollUpdate);
  updateScrollState();
})();
