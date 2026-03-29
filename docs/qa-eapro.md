# QA Checklist: eapro.in Workspace

Rigorous testing of AI integration, CVE lookup, and detailed analysis for the eapro.in workspace.

## Prerequisites

- [ ] Ollama running (`ollama serve`)
- [ ] Model pulled: `ollama pull huihui_ai/deepseek-r1-abliterated:8b`
- [ ] App running: `npm run dev`
- [ ] eapro.in workspace exists (create via domain selector if needed)

## 1. Workspace Setup

- [ ] Select or create eapro.in workspace
- [ ] Verify workspace appears in domain selector

## 2. Scans

- [ ] Run EASM scan for eapro.in (Attack Surface page)
- [ ] Run OSINT scan for eapro.in (OSINT Discovery page)
- [ ] Wait for scans to complete (status: completed)
- [ ] Verify findings appear in Findings page
- [ ] Verify recon modules appear in Intelligence page

## 3. Finding Enrichment

- [ ] Open Findings page, select a finding
- [ ] Click "Enrich with AI" – verify no error
- [ ] Verify enhanced description, contextual risks, additional remediation appear
- [ ] Click "Enrich all" – verify batch enrichment runs (toast shows count)

## 4. CVE Lookup

- [ ] Open a finding that mentions tech (e.g., Apache, nginx, PHP, Spring Boot)
- [ ] Click "Look up CVE" – verify no error
- [ ] Verify CVE badges appear (CVE-XXXX-XXXXX, CVSS score)
- [ ] Click CVE link – verify NVD page opens
- [ ] Verify Related CVEs section persists after closing/reopening finding

## 5. Detailed Analysis

- [ ] Open a finding
- [ ] Click "Detailed Analysis" – verify no error
- [ ] Verify analysis paragraph and recommendations appear
- [ ] Verify section persists after closing/reopening finding

## 6. AI Insights Tab

- [ ] Navigate to AI Insights (sidebar)
- [ ] Verify findings list loads
- [ ] Click "Generate" for Executive Summary – verify no error
- [ ] Verify summary, key risks, threat landscape appear
- [ ] Expand a finding with detailed analysis – verify analysis shows

## 7. Report Generation

- [ ] Navigate to Reports page
- [ ] Create new report for eapro.in workspace
- [ ] Wait for report to complete (status: completed)
- [ ] Open report – verify AI-generated executive summary (if Ollama enabled)
- [ ] Verify "(AI-generated)" badge when AI summary present

## 8. Import Scans

- [ ] Create sample nmap output: `nmap -sV -oN eapro.txt eapro.in` (or use existing)
- [ ] Navigate to Import Scans page
- [ ] Upload nmap file (drag-and-drop or file picker)
- [ ] Verify file appears in uploaded scans list
- [ ] Click "Consolidate" – verify no error
- [ ] Verify new/merged findings in Findings page

## 9. Fallback (Ollama Down)

- [ ] Stop Ollama (`ollama` process or `pkill ollama`)
- [ ] Verify app still loads (no crash)
- [ ] Verify "Enrich with AI" shows error toast (graceful)
- [ ] Verify "Generate" in AI Insights shows error (graceful)
- [ ] Restart Ollama and verify features work again

## Notes

- NVD CVE API: 5 req/30s without API key; set `NVD_API_KEY` for 50 req/30s
- CVE lookup may take 6+ seconds per request (rate limit)
- Detailed Analysis uses CVE data if available; run CVE lookup first for best results
