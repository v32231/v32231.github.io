---
layout: page
title: Categories
permalink: /categories/
---

<ul>
  {% for category in site.data.categories %}
    <li><a href="{{ category.url | relative_url }}">{{ category.label }}</a></li>
  {% endfor %}
</ul>
