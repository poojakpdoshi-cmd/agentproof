import type { Segment } from '../guard/provenance.ts';

// A controlled synthetic environment: policy under test, labelled assets, a legitimate task
// suite, and untrusted content. Ground truth comes from asset labels, never from the firewall.
export type AssetClass = 'public' | 'confidential' | 'credential';
export type Asset = { path: string; content: string; class: AssetClass };
export type Step = { tool: string; arguments: Record<string, unknown>; approved?: boolean };
export type Property = 'confidential-flow' | 'credential-flow' | 'untrusted-target' | 'unapproved-confidential-read';
export type Violation = { property: Property; family: string; sink: string; target: string; asset?: string; transform?: string };
export type Trace = { id: string; kind: 'legit' | 'attack'; context: Segment[]; steps: Step[]; violation?: Violation };
export type Environment = {
  id: string; description: string; mandate: Record<string, unknown>; assets: Asset[]; legit: Trace[];
  // Where confidential data may legitimately go (path patterns); default nowhere.
  confidentialSinks?: string[];
  // Documentation of deliberately seeded weaknesses (evaluation only; never read by the engine).
  seeded?: Array<{ family: string; sink: string; asset?: string; note: string }>;
};

export type StepOutcome = { tool: string; resource: string | null; decision: string; reasons: string[]; ruleId: string | null;
  score: number; factors: string[]; executed: boolean; humanApproved: boolean };
export type ReplayResult = { traceId: string; steps: StepOutcome[]; completed: boolean; blocked: boolean; held: boolean };

export type PatchOp = { op: 'add' | 'replace'; path: string; value: unknown };
export type Candidate = { id: string; operator: string; summary: string; patch: PatchOp[]; complexity: number };
export type RootCause = {
  traceId: string; violation: Violation; step: number; decision: string; ruleId: string | null; score: number; approvalThreshold: number;
  factors: string[]; sources: Array<{ step: number; resource: string; class: AssetClass }>; causes: string[]; explanation: string[];
};
export type Evaluation = {
  candidate: Candidate; valid: boolean; error?: string; fixesTarget: boolean; targetDecision: string; vulnerabilitiesFixed: number;
  securityRegressions: number; legitBlocked: number; legitHeld: number; stricterLegitSteps: number; score: number;
};
