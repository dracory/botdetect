package botdetect

// == BOT PATH PATTERNS ========================================================

// botPathPatterns contains lowercase path substrings for files that
// legitimate crawlers request but no human browser ever does. These are
// universal across all websites regardless of tech stack.
//
// favicon.ico is excluded because browsers automatically request it.
// /.well-known/ is excluded because browsers use it for legitimate
// purposes (e.g. /.well-known/change-password for credential discovery).
//
// Matching is suffix-on-last-segment (see IsBotPath), so filename variants
// each need an explicit entry — e.g. "sitemap.xml" does not catch
// "sitemap_index.xml". Prefix-matched names (e.g. google*.html site
// verification files) cannot be expressed with this list.
var botPathPatterns = []string{
	"ads.txt",
	"ai.txt", // spawning.ai proposal for AI-crawler permissions;
	// rare false positive on files like "samurai.txt" (suffix match)
	"bingsiteauth.xml",
	"browserconfig.xml",      // IE/Edge tile config probed by some crawlers
	"clientaccesspolicy.xml", // legacy Silverlight policy file, only scanners fetch it
	"crossdomain.xml",        // legacy Flash policy file, only scanners fetch it
	"dnt-policy.txt",
	"humans.txt",
	"llms.txt",      // llmstxt.org manifest for LLM crawlers
	"llms-full.txt", // llmstxt.org full-content variant
	"robots.txt",
	"sitemap.xml",
	"security.txt",
	"sellers.json",
	"sitemap_index.xml", // Yoast/RankMath sitemap variant
	"sitemap-index.xml", // hyphenated sitemap variant
	"sitemap.xml.gz",    // compressed sitemap
}

// maliciousPathPatterns contains lowercase path substrings for endpoints
// that are never legitimate on any properly-configured website, regardless
// of tech stack. A single request to any of these is strong evidence of a
// vulnerability scanner or malicious bot.
//
// Stack-dependent patterns (e.g. .php, .asp, wp-admin) are intentionally
// excluded — they are malicious on some stacks but legitimate on others.
// Consumers should add their own stack-specific patterns on top.
//
// Matching (see IsMaliciousPath): file patterns match as a suffix of the
// last path segment; directory patterns (trailing "/") match a whole path
// segment. All entries must be lowercase — the path is lowercased before
// matching but the pattern is compared as-is.
var maliciousPathPatterns = []string{
	".aws/",    // AWS credentials directory
	".claude/", // Claude Code config directory
	".clinerules",
	".continue/",   // Continue.dev config — may contain API keys
	".cursor/",     // Cursor config dir — mcp.json may contain secrets
	".cursorrules", // Cursor rules file
	".devin/",      // Devin config dir — mcp.json may contain secrets
	".ds_store",    // macOS metadata leak (path is lowercased before matching)
	".env",
	".git/",
	".htpasswd",
	".npmrc", // npm config, can leak auth tokens
	".ssh/",  // SSH keys directory
	".svn/",
	".windsurf/",                 // Windsurf config directory
	".windsurfrules",             // Windsurf rules file
	"agents.md",                  // AGENTS.md — probed for agent-instruction leaks
	"claude.md",                  // CLAUDE.md agent instructions
	"claude_desktop_config.json", // Claude Desktop MCP config — contains secrets
	"copilot-instructions.md",    // GitHub Copilot instructions (.github/)
	"gemini.md",                  // GEMINI.md agent instructions
	"id_rsa",                     // SSH private key
	"mcp.json",                   // MCP server config — often contains API keys/tokens
	"shell.php",
}
