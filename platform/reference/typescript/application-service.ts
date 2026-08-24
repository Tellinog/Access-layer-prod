import { requireCapability, type RequestContext } from "./request-context.js";

export const EXAMPLE_READ = "template-project:example:read" as const;

export interface ExampleRecord { id: string; name: string; status: "active" | "inactive"; }
export interface ExampleRepository { findVisibleById(id: string, context: RequestContext): Promise<ExampleRecord | null>; }

export async function getExample(context: RequestContext, exampleId: string, repository: ExampleRepository): Promise<ExampleRecord> {
  requireCapability(context, EXAMPLE_READ);
  const normalisedId = exampleId.trim();
  if (!normalisedId || normalisedId.length > 128) throw new Error("EXAMPLE_ID_INVALID");
  const record = await repository.findVisibleById(normalisedId, context);
  if (!record) throw new Error("EXAMPLE_NOT_FOUND");
  return record;
}
