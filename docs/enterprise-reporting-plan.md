# Enterprise Reporting Upgrade Plan

## Overview

This document outlines the enterprise reporting upgrade for Cyber-Shield-Pro, designed to meet the needs of security teams, compliance officers, and executive stakeholders in larger organizations.

## Current State

- **Report types:** Executive Summary, Full Report, Evidence Pack
- **Export:** PDF only (client-side via jsPDF)
- **Content:** Findings, attack surface, security headers, cloud footprint, OSINT discovery, IP reputation
- **Lifecycle:** Create → Generate → View → Export PDF

## Upgrade Roadmap

### Phase 1: Multi-Format Export & Lifecycle (Implemented)

| Feature | Description | Status |
|---------|-------------|--------|
| CSV Export | Findings and summary data as CSV for spreadsheets | ✅ |
| Excel Export | Full report data in .xlsx format | ✅ |
| Report Delete | Remove reports from workspace | ✅ |
| Posture Trend | Include posture history in report content | ✅ |

### Phase 2: Branding & Customization (Planned)

| Feature | Description |
|---------|-------------|
| Report Branding | Company name, logo URL, custom colors |
| Report Templates | Customizable section order and visibility |
| Watermarking | Optional "Confidential" / "Draft" watermarks |

### Phase 3: Automation & Distribution (Planned)

| Feature | Description |
|---------|-------------|
| Scheduled Reports | Cron-based generation (daily/weekly/monthly) |
| Email Distribution | Send reports to configured recipients |
| Report Archive | Retention policy and archival |

### Phase 4: Advanced Analytics (Planned)

| Feature | Description |
|---------|-------------|
| Multi-Workspace Reports | Aggregate across workspaces |
| Trend Comparison | Period-over-period analysis |
| Compliance Mapping | Map findings to frameworks (NIST, CIS, etc.) |

## Technical Implementation

### Export Formats

- **PDF:** Existing jsPDF-based generation (server + client)
- **CSV:** Findings table with headers: ID, Title, Severity, Status, Category, Affected Asset, Description
- **Excel:** xlsx library; multiple sheets: Summary, Findings, Attack Surface, Security Headers

### API Endpoints

```
GET  /api/workspaces/:workspaceId/reports/:reportId/export?format=pdf|csv|xlsx
DELETE /api/workspaces/:workspaceId/reports/:reportId
```

### Report Content Enhancements

- `postureTrend`: Last N posture snapshots for trend visualization
- `reportMetadata`: Version, generated-by, workspace name

## Environment Variables (Phase 2)

```
REPORT_COMPANY_NAME=Acme Security
REPORT_LOGO_URL=https://...
REPORT_WATERMARK=Confidential
```
