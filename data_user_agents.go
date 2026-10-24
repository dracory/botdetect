package botdetect

// == BOT USER-AGENT PATTERNS ==================================================

// botUserAgentBroadPatterns contains lowercase substrings that indicate a bot,
// crawler, spider, or automated tool but are short enough to cause false
// positives if matched as plain substrings (e.g. "bot" inside "RoboBotonic").
// These are matched with a word-boundary check: the pattern must be followed
// by a non-alphanumeric character (or end of string).
//
// Specific bot substrings live in botClassifications (data_bot_classes.go),
// where each token is paired with its normalized Name and BotClass.
var botUserAgentBroadPatterns = []string{
	"bot",
	"crawler",
	"spider",
	"scraper",
	"slurp",
}
