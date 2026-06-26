/**
 * Curated poll-first trigger templates.
 *
 * Hosted routers (Composio, Zapier, …) ship a catalog of provider-push triggers — "new GitHub
 * issue", "new Gmail message", "new Slack message". MCP Switchboard can't depend on provider push
 * (it is local-first and behind NAT), so it offers the SAME catalog as POLL recipes: each
 * template pre-fills the detection wiring (which list field is the array, which field is the
 * unique key, a sane interval, sensible default args) for a common "watch X for new items"
 * pattern. The operator only has to point it at the exposed tool their mounted server actually
 * provides — `templateToDefinition` stamps the rest into a ready `TriggerDefinition`.
 *
 * This module is PURE DATA + two pure functions. No I/O, no config, no registry — so the
 * dashboard, the CLI, and the verifier all read the identical catalog.
 */

import type { TriggerDefinition } from "./types.js";

/** A reusable trigger recipe. `tool_hint` is the bare upstream tool name WITHOUT a server prefix. */
export interface TriggerTemplate {
  /** Stable template slug (e.g. `github-new-issues`). */
  id: string;
  /** Human label for the picker. */
  name: string;
  /** One-line description of what the recipe watches. */
  description: string;
  /** Grouping for the picker (the provider/toolkit family). */
  category: string;
  /**
   * The bare upstream tool this recipe polls, e.g. `list_issues` — NO server prefix. The operator
   * pairs it with the exposed name their mounted server provides (e.g. `github__list_issues`).
   */
  tool_hint: string;
  /** Suggested default arguments for the polled tool. */
  args?: Record<string, unknown>;
  /**
   * Dot-path to the result array for ITEM-LEVEL detection (new keys fire). Omit for a recipe that
   * fires on ANY whole-response change (hash detection) — e.g. watching an HTTP page or feed.
   */
  item_path?: string;
  /** Unique-per-element field for item detection (e.g. `id`, `number`, `sha`). Pairs with `item_path`. */
  item_key?: string;
  /** Suggested poll interval in seconds. */
  interval_seconds: number;
}

/**
 * The shipped catalog. Item-detection recipes name the array path + key; the two hash recipes
 * (HTTP page, RSS/Atom feed) omit both so any change to the fetched body fires once. Paths/keys
 * follow each provider's common MCP result shape; the operator can override any of them.
 */
export const TRIGGER_TEMPLATES: readonly TriggerTemplate[] = [
  {
    id: "github-new-issues",
    name: "New GitHub issues",
    description: "Fires when an issue is opened in a repository.",
    category: "GitHub",
    tool_hint: "list_issues",
    args: { state: "open" },
    item_path: "",
    item_key: "number",
    interval_seconds: 120,
  },
  {
    id: "github-new-pull-requests",
    name: "New GitHub pull requests",
    description: "Fires when a pull request is opened.",
    category: "GitHub",
    tool_hint: "list_pull_requests",
    args: { state: "open" },
    item_path: "",
    item_key: "number",
    interval_seconds: 120,
  },
  {
    id: "github-new-commits",
    name: "New GitHub commits",
    description: "Fires when a commit lands on a branch.",
    category: "GitHub",
    tool_hint: "list_commits",
    item_path: "",
    item_key: "sha",
    interval_seconds: 300,
  },
  {
    id: "gmail-new-mail",
    name: "New Gmail message",
    description: "Fires when an unread message arrives.",
    category: "Gmail",
    tool_hint: "list_messages",
    args: { query: "is:unread" },
    item_path: "messages",
    item_key: "id",
    interval_seconds: 120,
  },
  {
    id: "calendar-new-events",
    name: "New calendar event",
    description: "Fires when an event is added to the calendar.",
    category: "Calendar",
    tool_hint: "list_events",
    item_path: "items",
    item_key: "id",
    interval_seconds: 300,
  },
  {
    id: "linear-new-issues",
    name: "New Linear issues",
    description: "Fires when an issue is created in Linear.",
    category: "Linear",
    tool_hint: "list_issues",
    item_path: "issues",
    item_key: "id",
    interval_seconds: 120,
  },
  {
    id: "jira-new-issues",
    name: "New Jira issues",
    description: "Fires when an issue matches the search and is new.",
    category: "Jira",
    tool_hint: "search_issues",
    item_path: "issues",
    item_key: "key",
    interval_seconds: 180,
  },
  {
    id: "slack-channel-activity",
    name: "New Slack messages",
    description: "Fires when a message is posted to a channel.",
    category: "Slack",
    tool_hint: "conversations_history",
    item_path: "messages",
    item_key: "ts",
    interval_seconds: 60,
  },
  {
    id: "notion-database-changes",
    name: "New Notion database rows",
    description: "Fires when a page is added to a database.",
    category: "Notion",
    tool_hint: "query_database",
    item_path: "results",
    item_key: "id",
    interval_seconds: 300,
  },
  {
    id: "http-page-change",
    name: "Web page changed",
    description: "Fires when the fetched page body changes at all (whole-response hash).",
    category: "HTTP",
    tool_hint: "fetch",
    interval_seconds: 600,
  },
  {
    id: "rss-feed-change",
    name: "RSS / Atom feed changed",
    description: "Fires when a feed's contents change (whole-response hash).",
    category: "HTTP",
    tool_hint: "fetch",
    interval_seconds: 600,
  },
] as const;

/** The catalog, as a plain array (for JSON responses + the dashboard). */
export function listTriggerTemplates(): TriggerTemplate[] {
  return [...TRIGGER_TEMPLATES];
}

/** Look up one template by slug. */
export function getTriggerTemplate(templateId: string): TriggerTemplate | undefined {
  return TRIGGER_TEMPLATES.find((t) => t.id === templateId);
}

/** Options that bind a template to a concrete mounted tool. */
export interface TemplateInstanceOptions {
  /** Stable id for the NEW trigger definition (namespaces its persisted seen-state). */
  id: string;
  /** The exposed tool name to actually poll — server-prefixed, e.g. `github__list_issues`. */
  tool: string;
  /** Human label override (defaults to the template's name). */
  name?: string;
  /** Extra/override args merged ON TOP of the template's defaults. */
  args?: Record<string, unknown>;
  /** Poll interval override in seconds (defaults to the template's). */
  interval_seconds?: number;
}

/**
 * Stamp a template into a ready-to-mount `TriggerDefinition`. The template supplies the detection
 * wiring (item_path/item_key) and default args/interval; the caller supplies the trigger id and
 * the concrete exposed tool name, and may override the name, args (merged), and interval. Throws
 * if `templateId` is unknown so a bad reference fails loud rather than producing a dead trigger.
 */
export function templateToDefinition(templateId: string, opts: TemplateInstanceOptions): TriggerDefinition {
  const tpl = getTriggerTemplate(templateId);
  if (!tpl) throw new Error(`unknown trigger template '${templateId}'`);

  const mergedArgs = { ...(tpl.args ?? {}), ...(opts.args ?? {}) };
  const def: TriggerDefinition = {
    id: opts.id,
    name: opts.name ?? tpl.name,
    tool: opts.tool,
    interval_seconds: opts.interval_seconds ?? tpl.interval_seconds,
    enabled: true,
  };
  if (Object.keys(mergedArgs).length > 0) def.args = mergedArgs;
  if (tpl.item_path !== undefined) def.item_path = tpl.item_path;
  if (tpl.item_key !== undefined) def.item_key = tpl.item_key;
  return def;
}
