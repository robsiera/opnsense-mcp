import { z } from "zod";

const segment = z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/);

export const instanceField = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/)
  .optional()
  .describe("Named OPNsense instance from the server config; omits to use the configured default");

export const optionalInstanceShape = {
  instance: instanceField,
};

export const apiRequestShape = {
  ...optionalInstanceShape,
  module: segment.describe("API module, for example 'core' or 'firewall'"),
  controller: segment.describe("API controller, for example 'system' or 'filter'"),
  command: segment.describe("API command, for example 'status' or 'search_rule'"),
  parameters: z.array(z.string().min(1).max(1024)).max(16).optional().describe("Ordered URL path parameters"),
  query: z
    .record(segment, z.union([z.string(), z.number(), z.boolean()]))
    .optional()
    .describe("Query-string parameters"),
  body: z.unknown().optional().describe("JSON request body. OPNsense model endpoints usually require a named root object."),
  method: z.enum(["GET", "POST"]).optional().describe("Defaults to GET without a body and POST with a body"),
};

export const apiRequestSchema = z.object(apiRequestShape);
