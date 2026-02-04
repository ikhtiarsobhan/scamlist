-- Minimal schema upgrades for existing databases

ALTER TABLE public.reports
  ADD COLUMN IF NOT EXISTS suggested_classification text NOT NULL DEFAULT 'unclassified',
  ADD COLUMN IF NOT EXISTS classification text NOT NULL DEFAULT 'unclassified',
  ADD COLUMN IF NOT EXISTS classified_by text,
  ADD COLUMN IF NOT EXISTS classified_on timestamptz,
  ADD COLUMN IF NOT EXISTS is_verified boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS verified_by text,
  ADD COLUMN IF NOT EXISTS verified_on timestamptz;

CREATE INDEX IF NOT EXISTS reports_flagged_idx ON public.reports(is_flagged);
