/**
 * Response Formatting Utilities
 *
 * Helpers for formatting tool responses in JSON or Markdown.
 */

import { CrowdStrikeApiError, formatErrorForLogging } from './errors.js';

/**
 * Response format type
 */
export type ResponseFormat = 'json' | 'markdown';

/**
 * MCP tool response type
 * Note: Index signature required for MCP SDK 1.25+ compatibility
 */
export interface ToolResponse {
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

/**
 * Format a successful response
 */
export function formatResponse(
  data: unknown,
  format: ResponseFormat,
  _entityType: string
): ToolResponse {
  // Always use JSON for CrowdStrike responses - cleaner for security data
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

/**
 * Format an error response
 */
export function formatError(error: unknown): ToolResponse {
  const errorInfo = formatErrorForLogging(error);

  let message: string;
  if (error instanceof CrowdStrikeApiError) {
    message = `Error: ${error.message}`;
    if (error.retryable) {
      message += ' (retryable)';
    }
  } else if (error instanceof Error) {
    message = `Error: ${error.message}`;
  } else {
    message = `Error: ${String(error)}`;
  }

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({ error: message, details: errorInfo }, null, 2),
      },
    ],
    isError: true,
  };
}
