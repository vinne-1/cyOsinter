ALTER TABLE "findings"
ADD COLUMN IF NOT EXISTS "check_id" text;
--> statement-breakpoint
ALTER TABLE "findings"
ADD COLUMN IF NOT EXISTS "resource_type" text;
--> statement-breakpoint
ALTER TABLE "findings"
ADD COLUMN IF NOT EXISTS "resource_id" text;
--> statement-breakpoint
ALTER TABLE "findings"
ADD COLUMN IF NOT EXISTS "provider" text;
--> statement-breakpoint
ALTER TABLE "findings"
ADD COLUMN IF NOT EXISTS "compliance_tags" text[] DEFAULT '{}'::text[];
--> statement-breakpoint

CREATE TABLE IF NOT EXISTS "risk_items" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "workspace_id" varchar NOT NULL,
  "related_finding_id" varchar,
  "fingerprint" text NOT NULL,
  "title" text NOT NULL,
  "description" text NOT NULL,
  "category" text DEFAULT 'technical' NOT NULL,
  "likelihood" text DEFAULT 'medium' NOT NULL,
  "impact" text DEFAULT 'medium' NOT NULL,
  "risk_score" integer DEFAULT 4 NOT NULL,
  "risk_level" text DEFAULT 'medium' NOT NULL,
  "owner" text,
  "treatment" text DEFAULT 'mitigate' NOT NULL,
  "treatment_plan" text,
  "status" text DEFAULT 'open' NOT NULL,
  "review_cadence_days" integer DEFAULT 90 NOT NULL,
  "review_notes" text,
  "last_reviewed_at" timestamp,
  "created_at" timestamp DEFAULT now(),
  "updated_at" timestamp DEFAULT now(),
  CONSTRAINT "risk_items_workspace_fingerprint_unique" UNIQUE("workspace_id", "fingerprint")
);
--> statement-breakpoint

CREATE TABLE IF NOT EXISTS "policy_documents" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "workspace_id" varchar NOT NULL,
  "policy_type" text NOT NULL,
  "title" text NOT NULL,
  "version" text DEFAULT '1.0' NOT NULL,
  "effective_date" timestamp DEFAULT now() NOT NULL,
  "content" text NOT NULL,
  "created_by" varchar,
  "created_at" timestamp DEFAULT now(),
  "updated_at" timestamp DEFAULT now(),
  CONSTRAINT "policy_documents_workspace_type_unique" UNIQUE("workspace_id", "policy_type")
);
--> statement-breakpoint

CREATE TABLE IF NOT EXISTS "questionnaire_runs" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "workspace_id" varchar NOT NULL,
  "questionnaire_type" text DEFAULT 'security_baseline' NOT NULL,
  "total_questions" integer DEFAULT 0 NOT NULL,
  "auto_answered" integer DEFAULT 0 NOT NULL,
  "manual_required" integer DEFAULT 0 NOT NULL,
  "coverage_pct" integer DEFAULT 0 NOT NULL,
  "answers" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "created_by" varchar,
  "created_at" timestamp DEFAULT now()
);
--> statement-breakpoint

DO $$ BEGIN
 ALTER TABLE "risk_items" ADD CONSTRAINT "risk_items_workspace_fk" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "risk_items" ADD CONSTRAINT "risk_items_finding_fk" FOREIGN KEY ("related_finding_id") REFERENCES "findings"("id") ON DELETE set null ON UPDATE no action;
EXCEPTION WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "policy_documents" ADD CONSTRAINT "policy_documents_workspace_fk" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "policy_documents" ADD CONSTRAINT "policy_documents_created_by_fk" FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE set null ON UPDATE no action;
EXCEPTION WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "questionnaire_runs" ADD CONSTRAINT "questionnaire_runs_workspace_fk" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "questionnaire_runs" ADD CONSTRAINT "questionnaire_runs_created_by_fk" FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE set null ON UPDATE no action;
EXCEPTION WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint

CREATE INDEX IF NOT EXISTS "risk_items_workspace_id_idx" ON "risk_items" USING btree ("workspace_id");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "policy_documents_workspace_id_idx" ON "policy_documents" USING btree ("workspace_id");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "questionnaire_runs_workspace_id_idx" ON "questionnaire_runs" USING btree ("workspace_id");

