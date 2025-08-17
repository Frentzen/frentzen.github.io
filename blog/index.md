---
layout: page
title: Blog
permalink: /blog/
---

{% assign posts = site.posts %}
{% for post in posts %}
<article class="post">
  <h2><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
  <small>{{ post.date | date: site.minima.date_format }}</small>
  {% if post.excerpt %}
    <div class="post-excerpt">
      {{ post.excerpt }}
    </div>
  {% else %}
    <p>{{ post.description | default: post.content | strip_html | truncate: 200 }}</p>
  {% endif %}
</article>
<hr />
{% endfor %}
