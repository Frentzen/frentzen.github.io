---
layout: page
title: Home
permalink: /
---

# Hey, I'm Frentzen

Security engineer. I break and then fix things—API security, mobile, and automation.

- Latest article: [read it here]({{ site.posts.first.url | relative_url }})
- See all posts → [Blog](/blog/)

## Latest posts

<ul class="post-list">
  {% assign latest = site.posts | slice: 0, 5 %}
  {% for post in latest %}
    <li>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
      <small> — {{ post.date | date: site.minima.date_format }}</small>
      <div>{{ post.excerpt | default: post.description | default: post.content | strip_html | truncate: 160 }}</div>
    </li>
  {% endfor %}
</ul>

<p><a href="/blog/">→ Browse all posts</a></p>
