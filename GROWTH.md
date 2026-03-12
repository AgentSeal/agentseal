# AgentSeal Growth Playbook

> A living document for scaling AgentSeal's visibility and community. Contributions welcome!

## TL;DR

AgentSeal solves a real, growing problem: **AI agents are shipping to production without security audits**. As coding agents (Claude Code, Cursor, Copilot) go mainstream and MCP adoption accelerates, the attack surface is exploding. You're positioned to be the security layer the ecosystem needs.

---

## Positioning

### What Makes AgentSeal Different

| Competitor | Focus | AgentSeal's Edge |
|------------|-------|------------------|
| Lakera | Prompt injection as a service | You're **local-first** (no data leaves the machine) + cover MCP, skills, supply chain |
| Rebuff | Prompt injection library | You're a **full toolkit** (guard → shield → scan → scan-mcp) |
| Promptfoo | LLM eval framework | You're **security-specialized**, not general eval |
| OWASP LLM Top 10 | Guidelines | You're **actionable tooling**, not just documentation |

**Your one-liner:** "Find out if your AI agent can be hacked — before someone else does."

### Target Users

1. **Individual developers** building with Claude Code, Cursor, Windsurf → entry point via `agentseal guard`
2. **Security teams at AI companies** evaluating agent risk → enterprise pipeline integration
3. **Open-source agent maintainers** (OpenClaw, AutoGPT, etc.) → badge + CI integration
4. **Red teamers / security researchers** → SealBench dataset, research collaboration

---

## Visibility Checklist

### Awesome Lists to Submit To

| List | Link | Fit | Status |
|------|------|-----|--------|
| awesome-llm-security | [github.com/corca-ai/awesome-llm-security](https://github.com/corca-ai/awesome-llm-security) | ⭐⭐⭐ Perfect | ⬜ Submit PR |
| awesome-mcp-servers | [github.com/wong2/awesome-mcp-servers](https://github.com/wong2/awesome-mcp-servers) | ⭐⭐⭐ Add under "Security" | ⬜ Submit PR |
| awesome-ai-agents | [github.com/e2b-dev/awesome-ai-agents](https://github.com/e2b-dev/awesome-ai-agents) | ⭐⭐ As tooling | ⬜ Submit PR |
| awesome-llm-apps | [github.com/Shubhamsaboo/awesome-llm-apps](https://github.com/Shubhamsaboo/awesome-llm-apps) | ⭐⭐ Under "Security" | ⬜ Submit PR |
| awesome-claude | [github.com/anthropics/awesome-claude](https://github.com/anthropics/awesome-claude) | ⭐⭐ Dev tools | ⬜ Submit PR |

**PR Template:**
```markdown
## Add AgentSeal - Security toolkit for AI agents

AgentSeal scans machines for dangerous agent skills/configs, monitors supply chain 
attacks, and tests prompt injection resistance. CLI + SDK.

- GitHub: https://github.com/AgentSeal/agentseal
- Stars: 118+
- Languages: Python, TypeScript

**Why it fits:** [Explain relevance to the list's focus]
```

### Community Hubs

| Platform | Action | Priority |
|----------|--------|----------|
| Hacker News | Submit "Show HN: AgentSeal – security toolkit for AI agents" | ⭐⭐⭐ |
| r/MachineLearning | Post about toxic flow detection + supply chain attacks | ⭐⭐⭐ |
| r/LocalLLaMA | Highlight Ollama support (free local scanning) | ⭐⭐⭐ |
| r/netsec | Technical deep-dive on MCP security risks | ⭐⭐ |
| Twitter/X | Thread: "I scanned 50 popular MCP configs. Here's what I found." | ⭐⭐⭐ |
| Anthropic Discord | Share in #developer-tools | ⭐⭐ |
| AI security newsletters | Pitch to tldrsec.com, AI Security Weekly | ⭐⭐ |

---

## Content Strategy

### High-Impact Content Ideas

1. **"The State of AI Agent Security" Report**
   - Scan 100+ GitHub repos with MCP configs
   - Aggregate anonymized stats (% with dangerous permissions, toxic flows)
   - Visual report with embeddable badges
   - *Target: 20+ citations/backlinks*

2. **MCP Security Deep-Dive**
   - Explain tool poisoning, cross-server collusion
   - Real examples of how `filesystem + slack = exfiltration`
   - *Target: r/netsec front page*

3. **"I Hacked My Own AI Agent" Series**
   - Step-by-step prompt injection tutorials
   - Show AgentSeal detecting each attack
   - *Target: Dev.to trending, YouTube shorts*

4. **Security Badge Program**
   - `[![AgentSeal Verified](badge-url)](scan-results-url)`
   - Free for open-source projects
   - *Target: 50 repos displaying the badge*

### Writing Style

- **Lead with the problem**: "Your AI agent has access to your filesystem, API keys, and email. Have you audited what it can do?"
- **Show, don't tell**: Screenshots of terminal output, real scan results
- **Be specific**: "82 extraction probes + 109 injection probes" > "comprehensive testing"
- **Call to action**: Every post ends with `pip install agentseal && agentseal guard`

---

## Developer Relations

### Integration Targets

| Project | Integration | Value |
|---------|-------------|-------|
| Claude Code / Anthropic | Pre-install prompt to run `agentseal guard` | Millions of users |
| Cursor | Extension or recommended security check | Large developer base |
| OpenClaw | Built-in security scan skill | Aligned community |
| LangChain | Security docs section | Framework credibility |
| Vercel AI SDK | Example showing integration | Frontend devs |

### Research Collaboration

- Partner with OWASP LLM Working Group
- Contribute to academic papers on agent security
- Open-source SealBench dataset for reproducible benchmarks

---

## Rhythm

### Weekly
- [ ] Share one security insight on Twitter/X
- [ ] Respond to GitHub issues within 24h
- [ ] Check mentions on Reddit, HN

### Monthly  
- [ ] Publish one blog post or technical writeup
- [ ] Update SealBench with new attack patterns
- [ ] Submit to one awesome-list

### Quarterly
- [ ] Security report or research publication
- [ ] Conference talk submission (Black Hat, DEF CON AI Village, AI Engineer Summit)
- [ ] Review and update this playbook

---

## Metrics to Track

| Metric | Current | 3-Month Goal |
|--------|---------|--------------|
| GitHub Stars | 118 | 500 |
| PyPI Downloads/month | ~1k | 10k |
| npm Downloads/month | ~500 | 5k |
| Twitter Followers | ~200 | 2k |
| Awesome-list inclusions | 0 | 5+ |
| Security badge adoptions | 0 | 50 repos |

---

## Quick Wins

1. **Today**: Add AgentSeal to awesome-llm-security and awesome-mcp-servers
2. **This week**: Write a Twitter thread about MCP toxic flows
3. **This month**: Create the Security Badge program with GitHub Action

---

## Resources

- [Open-Source Launch Marketing Guide](https://github.com/AriaMoha/Launch-Playbook-for-Indie-Developers) - Tactical launch checklist
- [Developer Relations Best Practices](https://www.devrel.agency/handbook) - Community building
- [Gingiris Open Source Playbook](https://github.com/AFFiNE/awesome-affine/tree/main/growth) - Community distribution tactics

---

*This playbook is a starting point. Edit freely, track what works, and iterate.*
