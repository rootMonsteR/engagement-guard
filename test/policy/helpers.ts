import { join } from 'node:path'
import { type Engagement, EngagementSchema } from '../../src/engagement/schema.js'
import { type CommandAnalysis, createTargetExtractor } from '../../src/extract/extractor.js'

const CWD = join(import.meta.dirname, '..', 'fixtures', 'commands', 'cwd')
const extractor = createTargetExtractor()

/** The extractor's analysis of `command`, as the guard will see it. */
export const analyze = (
  command: string,
  shell: 'posix' | 'powershell' = 'posix',
): Promise<CommandAnalysis> => extractor.analyze(command, { cwd: CWD, shell })

/** A rules-of-engagement block with schema defaults plus `overrides`. */
export const roe = (overrides: Record<string, unknown> = {}): Engagement['roe'] =>
  EngagementSchema.shape.roe.parse(overrides)
