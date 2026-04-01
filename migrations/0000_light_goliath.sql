CREATE TABLE "alerts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"scan_id" varchar,
	"finding_id" varchar,
	"type" text NOT NULL,
	"title" text NOT NULL,
	"message" text NOT NULL,
	"severity" text DEFAULT 'info' NOT NULL,
	"read" boolean DEFAULT false NOT NULL,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"type" text NOT NULL,
	"value" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"first_seen" timestamp DEFAULT now(),
	"last_seen" timestamp DEFAULT now(),
	"metadata" jsonb,
	"tags" text[] DEFAULT '{}'::text[],
	CONSTRAINT "assets_workspace_type_value_unique" UNIQUE("workspace_id","type","value")
);
--> statement-breakpoint
CREATE TABLE "continuous_monitoring" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"target" text NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"iteration_count" integer DEFAULT 0,
	"progress_percent" integer,
	"progress_message" text,
	"current_step" text,
	"last_iteration_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"scan_id" varchar,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"severity" text NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"category" text NOT NULL,
	"affected_asset" text,
	"evidence" jsonb,
	"cvss_score" text,
	"remediation" text,
	"assignee" text,
	"discovered_at" timestamp DEFAULT now(),
	"resolved_at" timestamp,
	"tags" text[] DEFAULT '{}'::text[],
	"ai_enrichment" jsonb
);
--> statement-breakpoint
CREATE TABLE "posture_snapshots" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"scan_id" varchar,
	"target" text NOT NULL,
	"snapshot_at" timestamp DEFAULT now() NOT NULL,
	"surface_risk_score" integer,
	"tls_grade" text,
	"security_score" integer,
	"findings_count" integer DEFAULT 0,
	"critical_count" integer DEFAULT 0,
	"high_count" integer DEFAULT 0,
	"open_ports_count" integer DEFAULT 0,
	"waf_coverage" integer,
	"metadata" jsonb
);
--> statement-breakpoint
CREATE TABLE "recon_modules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"scan_id" varchar,
	"target" text NOT NULL,
	"module_type" text NOT NULL,
	"data" jsonb NOT NULL,
	"confidence" integer DEFAULT 0,
	"generated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "reports" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"title" text NOT NULL,
	"type" text NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"finding_ids" text[] DEFAULT '{}'::text[],
	"generated_at" timestamp,
	"content" jsonb,
	"summary" text
);
--> statement-breakpoint
CREATE TABLE "scans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"type" text NOT NULL,
	"target" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"started_at" timestamp,
	"completed_at" timestamp,
	"findings_count" integer DEFAULT 0,
	"summary" jsonb,
	"error_message" text,
	"progress_message" text,
	"progress_percent" integer,
	"current_step" text,
	"estimated_seconds_remaining" integer
);
--> statement-breakpoint
CREATE TABLE "scheduled_scans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"target" text NOT NULL,
	"scan_type" text DEFAULT 'full' NOT NULL,
	"cron_expression" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"last_run_at" timestamp,
	"next_run_at" timestamp,
	"last_scan_id" varchar,
	"mode" text DEFAULT 'standard' NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "uploaded_scans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" varchar NOT NULL,
	"filename" text NOT NULL,
	"file_type" text NOT NULL,
	"raw_content" text NOT NULL,
	"parsed_data" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "workspaces" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "workspaces_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE INDEX "alerts_workspace_id_idx" ON "alerts" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "alerts_read_idx" ON "alerts" USING btree ("read");--> statement-breakpoint
CREATE INDEX "assets_workspace_id_idx" ON "assets" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "findings_workspace_id_idx" ON "findings" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "findings_scan_id_idx" ON "findings" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "posture_snapshots_workspace_id_idx" ON "posture_snapshots" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "posture_snapshots_snapshot_at_idx" ON "posture_snapshots" USING btree ("snapshot_at");--> statement-breakpoint
CREATE INDEX "recon_modules_workspace_id_idx" ON "recon_modules" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "reports_workspace_id_idx" ON "reports" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "scans_workspace_id_idx" ON "scans" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "scans_status_idx" ON "scans" USING btree ("status");--> statement-breakpoint
CREATE INDEX "scheduled_scans_workspace_id_idx" ON "scheduled_scans" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "scheduled_scans_enabled_idx" ON "scheduled_scans" USING btree ("enabled");