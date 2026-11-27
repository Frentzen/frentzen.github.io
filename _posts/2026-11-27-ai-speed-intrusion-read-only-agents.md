---
layout: post
title: "Catching an AI-speed intrusion with read-only agents on Kubernetes"
date: 2026-11-27 09:00:00 +0000
categories: security
tags: [kubernetes, ai-agents, kagent, detection, appsec, incident]
description: "An alert fired on a decoy. A sandboxed, read-only AI agent cleared it, found the real compromise next door, and reconstructed how the attacker set it up — alert in 3 minutes, full investigation in 22."
---

At **19:35 UTC**, an operator with a shell on a Kubernetes pod read its service-account token and began probing the cluster API. Three minutes later an alert fired, on a *different* workload. By the time a human could have opened a dashboard, a read-only AI agent had already cleared the decoy, located the real intrusion, and worked out the setup step the attacker took eight minutes before the exploit.

Here is the verdict it posted, exactly as it reached the channel:

<div class="thread" role="img" aria-label="A Slack-style report card from the AIOps bot summarizing the investigation">
  <div class="hd"><span class="ch">#sec-payments</span><span>· thread</span><span class="live"><i></i>auto-posted · read-only</span></div>
  <div class="msg">
    <div class="av">A</div>
    <div class="bd">
      <div class="nm">AIOps<span class="bot">APP</span><span class="t">20:00</span></div>
      <p class="tx"><span class="verdict">True positive — but not the alert you think it is.</span> The <code>header_bypass</code> counter is a by-design decoy signal; the genuinely malicious activity is in the <code>payments-api</code> pod. The deployment was re-applied at 19:27 to turn on <code>automountServiceAccountToken</code>, handing the exploit a credential it would not otherwise have had. Token was read and decoded, then used for API discovery and enumeration of pods, secrets and namespaces <span class="tag-red">— all denied 403</span>. No NetworkPolicies exist; RBAC was the only control. Read-only investigation. Nothing was changed.</p>
      <div>
        <span class="pill">triage: suspect_compromise=true</span>
        <span class="pill">sweep: 2 ReplicaSets diffed</span>
        <span class="pill">sessions: 01a2195e, 01a21967</span>
      </div>
    </div>
  </div>
</div>
<p class="cap-redact">The report as rendered in Slack. Channel and session IDs redacted.</p>

## The problem

An attacker with a model in the loop does not pause between steps. Land code, read the token, hit the API, enumerate the namespace: one continuous transcript, seconds apart rather than the minutes or hours a human spends switching tools. That pace is the reason a dashboard-watching analyst loses. The obvious response is to put a model on defense too.

The catch is that a defensive agent with real cluster access becomes a new target and a new blast radius. If it can be steered by a prompt, or if it can write, it is the easiest lateral move an attacker could ask for. So the bar is two things at once: fast enough to keep up, and safe enough that it cannot be turned into a weapon. This pipeline is built for AI-speed attacks. We tested it against a human one, an operator exploiting the target by hand, and the agent still flagged the behavior as human-driven from the way the tooling stumbled and recovered.

## The system in one pass

Five stages, each a boundary the next one has to pass. The parts are ordinary: Prometheus, Argo, kagent, Slack. What matters is the wiring, because the AI only ever acts inside a box the previous stage drew for it.

<figure>
<svg viewBox="0 0 760 336" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Five-stage pipeline: detect, route, investigate, hand off, report, with the agents sandboxed on Agent Substrate reading the Kubernetes API read-only">
  <defs>
    <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#5c6773"/></marker>
    <marker id="art" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#33c2a6"/></marker>
  </defs>
  <text x="22" y="30" font-family="system-ui,sans-serif" font-size="15" font-weight="650" fill="#d7dee6">The agents only read; the workflow decides where they look</text>
  <g font-family="system-ui,sans-serif">
    <g><rect x="12" y="62" width="136" height="60" rx="9" fill="#0f141b" stroke="#5aa2ff" stroke-width="1.25"/><circle cx="28" cy="78" r="9" fill="#12181f" stroke="#5aa2ff"/><text x="28" y="82" text-anchor="middle" font-family="ui-monospace,monospace" font-size="11" fill="#5aa2ff">1</text><text x="80" y="94" text-anchor="middle" font-size="13.5" font-weight="620" fill="#d7dee6">Detect</text><text x="80" y="111" text-anchor="middle" font-size="10.5" fill="#8a97a6" font-family="ui-monospace,monospace">Prometheus</text></g>
    <g><rect x="162" y="62" width="136" height="60" rx="9" fill="#0f141b" stroke="#5aa2ff" stroke-width="1.25"/><circle cx="178" cy="78" r="9" fill="#12181f" stroke="#5aa2ff"/><text x="178" y="82" text-anchor="middle" font-family="ui-monospace,monospace" font-size="11" fill="#5aa2ff">2</text><text x="230" y="94" text-anchor="middle" font-size="13.5" font-weight="620" fill="#d7dee6">Route</text><text x="230" y="111" text-anchor="middle" font-size="10.5" fill="#8a97a6" font-family="ui-monospace,monospace">Argo</text></g>
    <g><rect x="312" y="62" width="136" height="60" rx="9" fill="#0f141b" stroke="#33c2a6" stroke-width="1.25"/><circle cx="328" cy="78" r="9" fill="#12181f" stroke="#33c2a6"/><text x="328" y="82" text-anchor="middle" font-family="ui-monospace,monospace" font-size="11" fill="#33c2a6">3</text><text x="380" y="94" text-anchor="middle" font-size="13.5" font-weight="620" fill="#d7dee6">Investigate</text><text x="380" y="111" text-anchor="middle" font-size="10.5" fill="#8a97a6" font-family="ui-monospace,monospace">kagent</text></g>
    <g><rect x="462" y="62" width="136" height="60" rx="9" fill="#0f141b" stroke="#33c2a6" stroke-width="1.25"/><circle cx="478" cy="78" r="9" fill="#12181f" stroke="#33c2a6"/><text x="478" y="82" text-anchor="middle" font-family="ui-monospace,monospace" font-size="11" fill="#33c2a6">4</text><text x="530" y="94" text-anchor="middle" font-size="13.5" font-weight="620" fill="#d7dee6">Hand off</text><text x="530" y="111" text-anchor="middle" font-size="10.5" fill="#8a97a6" font-family="ui-monospace,monospace">workflow</text></g>
    <g><rect x="612" y="62" width="136" height="60" rx="9" fill="#0f141b" stroke="#d8a34a" stroke-width="1.25"/><circle cx="628" cy="78" r="9" fill="#12181f" stroke="#d8a34a"/><text x="628" y="82" text-anchor="middle" font-family="ui-monospace,monospace" font-size="11" fill="#d8a34a">5</text><text x="680" y="94" text-anchor="middle" font-size="13.5" font-weight="620" fill="#d7dee6">Report</text><text x="680" y="111" text-anchor="middle" font-size="10.5" fill="#8a97a6" font-family="ui-monospace,monospace">Slack</text></g>
  </g>
  <g stroke="#5c6773" stroke-width="1.25" fill="none">
    <path d="M148 92H160" marker-end="url(#ar)"/>
    <path d="M298 92H310" marker-end="url(#ar)"/>
    <path d="M448 92H460" marker-end="url(#ar)"/>
    <path d="M598 92H610" marker-end="url(#ar)"/>
  </g>
  <path d="M380 124V176" stroke="#33c2a6" stroke-width="1.25" fill="none" marker-start="url(#art)" marker-end="url(#art)"/>
  <text x="388" y="154" font-family="ui-monospace,monospace" font-size="11" fill="#8a97a6">A2A</text>
  <g>
    <rect x="236" y="180" width="420" height="120" rx="11" fill="rgba(51,194,166,.05)" stroke="#33c2a6" stroke-width="1.25"/>
    <text x="252" y="203" font-family="ui-monospace,monospace" font-size="12" fill="#33c2a6">Agent Substrate · gVisor sandbox · read-only</text>
    <rect x="252" y="222" width="172" height="56" rx="8" fill="#0f141b" stroke="#2b7f72" stroke-width="1.1"/>
    <text x="338" y="246" text-anchor="middle" font-family="system-ui,sans-serif" font-size="13" font-weight="620" fill="#d7dee6">Triage agent</text>
    <text x="338" y="264" text-anchor="middle" font-family="ui-monospace,monospace" font-size="10.5" fill="#8a97a6">security analyst</text>
    <rect x="468" y="222" width="172" height="56" rx="8" fill="#0f141b" stroke="#2b7f72" stroke-width="1.1"/>
    <text x="554" y="246" text-anchor="middle" font-family="system-ui,sans-serif" font-size="13" font-weight="620" fill="#d7dee6">K8s sweep agent</text>
    <text x="554" y="264" text-anchor="middle" font-family="ui-monospace,monospace" font-size="10.5" fill="#8a97a6">signs of compromise</text>
    <path d="M424 250H466" stroke="#33c2a6" stroke-width="1.25" fill="none" marker-end="url(#art)"/>
  </g>
  <text x="446" y="241" text-anchor="middle" font-family="ui-monospace,monospace" font-size="9.5" fill="#8a97a6">compromise?</text>
  <g>
    <path d="M44 214c0-6 26-11 58-11s58 5 58 11v44c0 6-26 11-58 11s-58-5-58-11z" fill="#0f141b" stroke="#5c6773" stroke-width="1.1"/>
    <path d="M44 214c0 6 26 11 58 11s58-5 58-11" fill="none" stroke="#5c6773" stroke-width="1.1"/>
    <text x="102" y="246" text-anchor="middle" font-family="system-ui,sans-serif" font-size="12" font-weight="600" fill="#d7dee6">K8s API</text>
    <text x="102" y="262" text-anchor="middle" font-family="ui-monospace,monospace" font-size="10" fill="#49c66a">read-only</text>
  </g>
  <path d="M236 240H166" stroke="#5c6773" stroke-width="1.25" fill="none" marker-end="url(#ar)"/>
  <text x="200" y="233" text-anchor="middle" font-family="ui-monospace,monospace" font-size="9.5" fill="#8a97a6">view</text>
</svg>
<figcaption>Pipeline · blue = deterministic control plane, teal = sandboxed agents, amber = operator output</figcaption>
</figure>

The rule that makes it safe: **agents advise, the workflow decides.** An agent reports what it found; the deterministic engine reads that report and chooses what happens next. A confused or hijacked agent cannot redirect the investigation at a target of the attacker's choosing, because it never holds that authority.

Routing is table-driven. An alert's `category` label picks a mode, and the namespace maps to a fixed set of agents. The alert's free text never names the target. Channel membership decides who can ask about which namespace.

**`routing.json`**

```json
"namespaces": {
  "payments": { "k8sAgent": "platform-agent", "securityAgent": "secops-agent" }
},
"slackChannels": { "C0PAYMENTS": "payments" }
```

Each agent returns a small structured verdict the workflow can parse. The handoff from triage to the deeper sweep turns on a single boolean.

**triage verdict (A2A response)**

```json
{ "summary": "...",
  "evidence": ["..."],
  "indicators": ["check for blocked egress", "check SA token use"],
  "suspect_compromise": true }
```

## Why the analyst is caged

The defensive agents run as sandboxed actors on [kagent](https://kagent.dev)'s Agent Substrate, not as ordinary pods. That is what makes it safe to point a model at a live cluster during an incident. Four layers bound the damage, and they nest: a prompt-injected agent has to break all of them to do anything worse than read.

<figure>
<svg viewBox="0 0 760 270" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Nested containment: gVisor sandbox, then SPIFFE identity, then egress gateway, with a read-only agent and the Kubernetes API at the center">
  <text x="22" y="30" font-family="system-ui,sans-serif" font-size="15" font-weight="650" fill="#d7dee6">The worst a hijacked agent can do is read what it could already read</text>
  <rect x="30" y="52" width="700" height="196" rx="12" fill="rgba(51,194,166,.04)" stroke="#33c2a6" stroke-width="1.3"/>
  <text x="46" y="74" font-family="ui-monospace,monospace" font-size="12" fill="#33c2a6">gVisor sandbox · user-space kernel</text>
  <rect x="78" y="86" width="604" height="150" rx="11" fill="rgba(90,162,255,.04)" stroke="#5aa2ff" stroke-width="1.2"/>
  <text x="94" y="107" font-family="ui-monospace,monospace" font-size="12" fill="#5aa2ff">SPIFFE identity · per-agent, non-forgeable</text>
  <rect x="126" y="120" width="508" height="104" rx="10" fill="rgba(216,163,74,.04)" stroke="#d8a34a" stroke-width="1.2"/>
  <text x="142" y="141" font-family="ui-monospace,monospace" font-size="12" fill="#d8a34a">egress gateway · K8s API and nothing else</text>
  <rect x="180" y="156" width="400" height="56" rx="9" fill="#0f141b" stroke="#49c66a" stroke-width="1.3"/>
  <text x="380" y="180" text-anchor="middle" font-family="system-ui,sans-serif" font-size="13.5" font-weight="620" fill="#d7dee6">agent → Kubernetes API</text>
  <text x="380" y="199" text-anchor="middle" font-family="ui-monospace,monospace" font-size="11" fill="#49c66a">read-only RBAC · no write path</text>
  <g font-family="ui-monospace,monospace" font-size="10.5" fill="#f0655c">
    <text x="662" y="200" text-anchor="end">✗ no host</text>
    <text x="662" y="215" text-anchor="end">✗ no exfil</text>
    <text x="662" y="230" text-anchor="end">✗ no write</text>
  </g>
</svg>
<figcaption>Defense in depth for the defender itself: sandbox → identity → egress → read-only API</figcaption>
</figure>

Read access is scoped to exactly the namespaces an agent investigates, through the built-in `view` role, and nowhere near Secrets. There is no `apply`, no restart, no scale: the capability is absent, so it cannot be tricked into existing.

**read-only RBAC**

```yaml
kind: RoleBinding          # one namespace, built-in view role
metadata: { name: aiops-view, namespace: payments }
roleRef:  { kind: ClusterRole, name: view }
subjects: [{ kind: ServiceAccount, name: kagent-tools-ro, namespace: kagent }]
```

This cuts both ways. It contains the attacker, whose compromised pod is boxed by the same kind of RBAC and network policy. It also contains the defender, because an injected prompt cannot escalate past reading. We left remediation out of scope on purpose: an agent that can fix things is an agent that can be talked into fixing them in the attacker's favor, and that trade is not worth making until the read-only loop has earned trust.

## The incident, in full

The target namespace held two workloads. A deliberately weak login service (`customer-auth`) whose only flaw is a header that skips the password check, and the payments API (`payments-api`), a Next.js service carrying a known remote-code-execution bug ([CVE-2025-55182](https://github.com/l4rm4nd/CVE-2025-55182)). An operator attacked the second one by hand while the pipeline watched.

### The trigger fired on the decoy

Using the bypass raised a Prometheus counter, which fired on the login app. That alert is a by-design signal, and it had nothing to do with the real attack. It was enough to wake the pipeline.

**PrometheusRule**

```yaml
- alert: AuthHeaderBypassUsed
  expr: increase(app_auth_attempts_total{result="header_bypass"}[2m]) > 0
  labels: { severity: critical, namespace: payments, category: security }
```

### Triage cleared the decoy, then found the real thing

The triage agent read the login app's source from its ConfigMap, recognized the bypass as the documented, intended weakness, and confirmed the pod was unmodified with no path to code execution. Then it looked across the namespace and found the actual intrusion in the `payments-api` pod: the service-account token being read and decoded, followed by API discovery, `SelfSubjectAccessReview` calls, and attempts to list pods, secrets and namespaces. Every escalation returned `403`. It set `suspect_compromise: true` and the workflow handed off.

### The sweep found the setup step, and corrected the record

The sweep agent diffed the target's two ReplicaSets and surfaced the turning point: `automountServiceAccountToken` had been switched on in a rollout about eight minutes before the exploit. That is the attacker's own preparation, handing the exploit a credential it otherwise would not have had.

**payments-api · revision 1 → 2 (19:27:27Z)**

```diff
- automountServiceAccountToken: false
+ automountServiceAccountToken: true
```

It also corrected the containment story. There were no NetworkPolicies, so egress was never blocked; the pod reached and authenticated to the API server, and RBAC on a near-powerless default account was the only thing that stopped lateral movement. And from watching the tooling fail and recover, it judged this to be a person at the keyboard, not a canned scanner.

**container log · what the sweep read**

```text
/bin/sh: curl: not found
wget: unrecognized option: ca-certificate=...
/usr/bin/wget  ->  ok                         # fumbled, then adapted = human-driven
LISTPODS    code=403  pods is forbidden: ... cannot list "pods"
LISTSECRETS code=403  secrets is forbidden: ...
LISTNS      code=403  namespaces is forbidden: ... at the cluster scope
```

Start to finish, alert to a threaded, evidence-backed report, the run touched no `kubectl` command. The split is the honest headline: the alert landed three minutes after the exploit, and the two agents took twenty-two minutes to produce a full account. Finding the token flip meant diffing ReplicaSets and correlating timestamps across logs, the kind of cross-resource work that takes a human analyst a good while even when they know where to look. The agent did it in one unattended pass.

<figure>
<svg viewBox="0 0 760 300" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Timeline: exploit at 19:35, alert at 19:38, triage and sweep bars, report at 20:00">
  <text x="22" y="28" font-family="system-ui,sans-serif" font-size="15" font-weight="650" fill="#d7dee6">Alert in 3 minutes, full investigation in 22</text>
  <text x="22" y="47" font-family="ui-monospace,monospace" font-size="11" fill="#8a97a6">one incident, UTC</text>
  <g font-family="ui-monospace,monospace" font-size="10.5">
    <rect x="470" y="20" width="10" height="10" rx="2" fill="#f0655c"/><text x="486" y="29" fill="#8a97a6">attacker</text>
    <rect x="560" y="20" width="10" height="10" rx="2" fill="#5aa2ff"/><text x="576" y="29" fill="#8a97a6">pipeline</text>
    <rect x="648" y="20" width="10" height="10" rx="2" fill="#49c66a"/><text x="664" y="29" fill="#8a97a6">resolved</text>
  </g>
  <g font-family="ui-monospace,monospace" font-size="10.5" fill="#5c6773">
    <line x1="176" y1="66" x2="176" y2="272" stroke="#21262d"/><text x="176" y="60" text-anchor="middle">19:25</text>
    <line x1="243" y1="66" x2="243" y2="272" stroke="#21262d"/><text x="243" y="60" text-anchor="middle">19:30</text>
    <line x1="310" y1="66" x2="310" y2="272" stroke="#21262d"/><text x="310" y="60" text-anchor="middle">19:35</text>
    <line x1="377" y1="66" x2="377" y2="272" stroke="#21262d"/><text x="377" y="60" text-anchor="middle">19:40</text>
    <line x1="444" y1="66" x2="444" y2="272" stroke="#21262d"/><text x="444" y="60" text-anchor="middle">19:45</text>
    <line x1="511" y1="66" x2="511" y2="272" stroke="#21262d"/><text x="511" y="60" text-anchor="middle">19:50</text>
    <line x1="578" y1="66" x2="578" y2="272" stroke="#21262d"/><text x="578" y="60" text-anchor="middle">19:55</text>
    <line x1="645" y1="66" x2="645" y2="272" stroke="#21262d"/><text x="645" y="60" text-anchor="middle">20:00</text>
    <line x1="712" y1="66" x2="712" y2="272" stroke="#21262d"/><text x="712" y="60" text-anchor="middle">20:05</text>
  </g>
  <line x1="176" y1="66" x2="712" y2="66" stroke="#30363d" stroke-width="1.1"/>
  <line x1="310" y1="66" x2="310" y2="272" stroke="#f0655c" stroke-width="1.2" stroke-dasharray="4 4"/>
  <g font-family="system-ui,sans-serif" font-size="12.5">
    <text x="22" y="96" fill="#d7dee6">Attacker: token on</text>
    <path d="M283 90l8 8l-8 8l-8 -8z" fill="#f0655c"/>
    <text x="299" y="96" font-family="ui-monospace,monospace" font-size="10.5" fill="#8a97a6">19:27</text>
    <text x="22" y="128" fill="#d7dee6">Attacker: RCE + enum</text>
    <path d="M310 122l8 8l-8 8l-8 -8z" fill="#f0655c"/>
    <text x="326" y="128" font-family="ui-monospace,monospace" font-size="10.5" fill="#8a97a6">19:35 · token theft, 403s</text>
    <text x="22" y="160" fill="#d7dee6">Alert fires</text>
    <path d="M350 154l8 8l-8 8l-8 -8z" fill="#5aa2ff"/>
    <text x="366" y="160" font-family="ui-monospace,monospace" font-size="10.5" fill="#8a97a6">19:38 · on the decoy</text>
    <text x="22" y="192" fill="#d7dee6">Triage</text>
    <rect x="363" y="183" width="121" height="13" rx="6" fill="rgba(90,162,255,.18)" stroke="#5aa2ff" stroke-width="1.1"/>
    <text x="490" y="192" font-family="ui-monospace,monospace" font-size="10" fill="#8a97a6">clears decoy, finds intrusion</text>
    <text x="22" y="224" fill="#d7dee6">Sweep</text>
    <rect x="484" y="215" width="148" height="13" rx="6" fill="rgba(90,162,255,.18)" stroke="#5aa2ff" stroke-width="1.1"/>
    <text x="484" y="210" font-family="ui-monospace,monospace" font-size="10" fill="#8a97a6">diffs ReplicaSets: token switched on</text>
    <text x="22" y="256" fill="#d7dee6" font-weight="620">Report to Slack</text>
    <path d="M645 250l8 8l-8 8l-8 -8z" fill="#49c66a"/>
    <text x="661" y="256" font-family="ui-monospace,monospace" font-size="10.5" fill="#8a97a6">20:00</text>
  </g>
</svg>
<figcaption>Timeline · dashed line marks the exploit; most of the 22 minutes is model inference between tool calls</figcaption>
</figure>

## What it costs

The dials you set per environment, and where this build lands today:

| Issue | Impact | Fix |
|---|---|---|
| Model latency | 8–10 min per agent call; ~22 min end to end | Faster model, or tighter prompts that make fewer tool calls |
| Shared Harness | Concurrent investigations collide on task-state | Serialize now; give each agent its own harness to scale out |
| Alert dedup | Re-runs blocked by workflow name and repeat interval | Shorten retention in the lab; keep both as flood defense in prod |
| Target containment | A loosened target lets a compromise move | Ship locked (no token, egress DNS-only); loosen on purpose only |

### What a skeptic will ask

**Prompt injection through logs.** The agents read attacker-controlled container logs and ConfigMaps, which is the real injection surface. The system prompts treat all tool output as untrusted data and forbid acting on instructions found inside it, and the read-only cage means the worst a successful injection achieves is a wrong verdict, never a write. Hardening that verdict against adversarial logs is the next thing to test properly; we have not stress-tested it yet.

**Which model, and the cost.** The agents run DeepSeek through an OpenAI-compatible endpoint. Tokens are cheap at this volume; latency is the price, not dollars. A measured cost-per-investigation is on the list, and a faster model would help both numbers.

**What if no alert fires.** This loop is alert-driven, so it needs a signal. The `payments-api` activity alone was silent until the decoy woke the pipeline. Two answers close the gap: an operator can mention the bot in a channel to launch the same read-only investigation on demand, and the same workflow runs fine on a schedule for a periodic sweep.

## Takeaways

The attacker did everything an AI-driven intrusion does: landed code, stole a token, probed the API. What caught it was not a faster human but a defending agent that was quick *and* safe to run, because the safety is structural rather than promised.

Three choices carry it:

- **Sandboxed and read-only by construction.** The analyst runs behind a user-space kernel with its own identity, locked egress and no write path. A hijacked agent can only read what it could already read.
- **The workflow holds authority.** Routing and handoff are decided by a deterministic engine from a small verdict, so a wrong or adversarial agent cannot steer the investigation.
- **The operator stays in the loop, on one surface.** Findings and follow-ups share a Slack thread, fast enough to act on, with no terminal in sight.

The pieces are off the shelf. The contribution is the wiring: a way to point AI at a live cluster during an incident without handing an attacker a better foothold than they started with.

### References

<div class="refs">
  <a href="https://kagent.dev">kagent · Kubernetes-native agents</a>
  <a href="https://a2a-protocol.org">A2A · agent-to-agent protocol</a>
  <a href="https://spiffe.io">SPIFFE · workload identity</a>
  <a href="https://gvisor.dev">gVisor · user-space kernel</a>
  <a href="https://argoproj.github.io">Argo · Workflows &amp; Events</a>
  <a href="https://github.com/l4rm4nd/CVE-2025-55182">CVE-2025-55182 · Next.js RSC RCE</a>
</div>
