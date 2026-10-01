import re

# Content filter for user queries — blocks obvious prompt injection attempts
BLOCKED_PATTERNS = [
    r"ignore.*(?:previous|prior|above).*(?:instruction|rule|directive)",
    r"disregard.*(?:instruction|rule|guideline)",
    r"(?:reveal|show|display|output).*(?:system.*prompt|secret|flag|classified)",
    r"(?:system|internal).*(?:prompt|instruction|directive)",
    r"KX\{",
    r"(?:bypass|override|disable).*(?:filter|security|restriction|rule)",
    r"you\s+are\s+now\s+(?:a|an|in)",
    r"(?:pretend|act|imagine)\s+(?:you|that|as)",
    r"(?:new|override|updated)\s+(?:instruction|directive|rule|system)",
    r"(?:forget|clear)\s+(?:everything|all|instruction|rule)",
    r"DAN\b",
    r"jailbreak",
    r"(?:print|echo|dump).*(?:all|every).*(?:document|content|data)",
]

FILTER_REGEX = re.compile("|".join(BLOCKED_PATTERNS), re.IGNORECASE)


def is_query_safe(query: str) -> tuple[bool, str | None]:
    match = FILTER_REGEX.search(query)
    if match:
        return False, "Query blocked by content policy."
    return True, None
