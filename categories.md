---
layout: page
title: Categories
permalink: /categories/
eyebrow: List
description: Development / CTF/Wargame / BugBounty / Blog Docs / Papers & Conferences / Contests & Certifications
---

<div class="category-grid">
  {% for category in site.data.categories %}
    {% assign category_posts = site.categories[category.name] %}
    <a class="category-card" href="{{ category.url | relative_url }}">
      <span class="category-count">{{ category_posts | size }} posts</span>
      <h3>{{ category.label | default: category.name }}</h3>
    </a>
  {% endfor %}
</div>
