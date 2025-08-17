---
layout: page
title: Tags
permalink: /tags/
---

<ul class="tag-cloud">
{% assign tags = site.tags | sort %}
{% for tag in tags %}
  <li>
    <a href="#{{ tag[0] | slugify }}">{{ tag[0] }} ({{ tag[1].size }})</a>
  </li>
{% endfor %}
</ul>

{% for tag in tags %}
<h2 id="{{ tag[0] | slugify }}">{{ tag[0] }}</h2>
<ul>
  {% for post in tag[1] %}
    <li>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
      <small>— {{ post.date | date: site.minima.date_format }}</small>
    </li>
  {% endfor %}
</ul>
{% endfor %}
