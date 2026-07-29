---
layout: page
title: Tags
permalink: /tags/
---

{% assign sorted_tags = site.tags | sort %}

<div class="page-heading">
  <p class="page-heading__eyebrow">EXPLORE</p>
  <p class="page-heading__description">관심 있는 태그를 눌러 관련 글을 모아보세요.</p>
</div>

<nav class="tag-cloud" aria-label="전체 태그">
  {% for tag in sorted_tags %}
    <a class="tag-chip tag-chip--cloud" href="#{{ tag[0] | slugify }}">
      #{{ tag[0] }} <span>{{ tag[1].size }}</span>
    </a>
  {% endfor %}
</nav>

<div class="tag-sections">
  {% for tag in sorted_tags %}
    <section class="tag-section" id="{{ tag[0] | slugify }}">
      <div class="tag-section__header">
        <h2>#{{ tag[0] }}</h2>
        <span>{{ tag[1].size }} posts</span>
      </div>

      <div class="tag-post-list">
        {% for post in tag[1] %}
          <a class="tag-post" href="{{ post.url | relative_url }}">
            <span>{{ post.title }}</span>
            <time datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date: site.date_format }}</time>
          </a>
        {% endfor %}
      </div>
    </section>
  {% endfor %}
</div>
