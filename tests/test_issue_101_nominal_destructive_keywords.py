"""Destructive keywords whose lemma is also a noun or an adjective must not
fire on the nominal use (#101 follow-up).

`drop` and `clear` collide with "vertical drop", "the drop shadow", "a clear
error" and "makes that clear" — benign descriptions of read-only tools that the
destructive tier flagged. Measured against the 16,015-tool MCP010 conformance
corpus, the lemma alone accounted for 252 fires, most of them this class.

The cut must not cost real detections: a description states an operation far
more often in the imperative than in the third person, so rejecting the lemma
outright loses "Drop the table when done" and "clear the cache when full".
"""

import pytest

from mcp_guard.models import MCPCapability
from mcp_guard.parser import MCPParser


def parse_tool(**tool: object) -> MCPCapability:
    manifest = MCPParser.from_dict({"name": "srv", "tools": [tool]})
    return manifest.capabilities[0]


class TestNominalCollidingDestructiveKeywords:
    """The noun and adjective uses must be suppressed."""

    @pytest.mark.parametrize(
        "description",
        [
            "Vertical drop, base/summit elevation and average snowfall.",
            "Applies a multiply blend for the drop shadow and the curve of light.",
            "Returns a clear not-found error instead of raising.",
            "Give a clear verdict (likely eligible) for the applicant.",
            "Decide when the source makes that clear.",
            "Needs a clear next action for the champion.",
        ],
    )
    def test_nominal_use_is_not_destructive(self, description):
        cap = parse_tool(name="get_report", description=description)
        assert cap.is_destructive is False, description

    @pytest.mark.parametrize("keyword", ["drop", "clear"])
    def test_nominal_use_does_not_fire_the_keyword_helper(self, keyword):
        blob = "the drop shadow" if keyword == "drop" else "a clear error"
        assert not MCPParser._keyword_hit([keyword], "get_report", blob)


class TestVerbFormsStillFire:
    """The imperative, gerund, past and third person are real detections."""

    @pytest.mark.parametrize(
        "description",
        [
            "Drop the table when done.",
            "Drops the rows with no country assigned.",
            "Dropping any account with an expired lease.",
            "Cleared the cache before returning.",
            "Clearing the cache before every request.",
            "Returns a copy; clear the cache when full.",
        ],
    )
    def test_verb_position_is_destructive(self, description):
        cap = parse_tool(name="maintenance", description=description)
        assert cap.is_destructive is True, description


class TestOtherKeywordsUnaffected:
    """Only the two colliding lemmas are guarded."""

    @pytest.mark.parametrize(
        "description",
        [
            "Delete every record matching the filter.",
            "Removes the expired sessions from the pool.",
            "Purges the dead-letter queue.",
        ],
    )
    def test_unambiguous_keywords_keep_the_bare_lemma(self, description):
        cap = parse_tool(name="get_cleanup", description=description)
        assert cap.is_destructive is True, description

    def test_the_other_tiers_are_not_narrowed(self):
        """A guarded keyword only narrows itself; `_keyword_hit` dispatches on
        the keyword, so an unrelated keyword set is unaffected."""
        cap = parse_tool(
            name="get_report", description="Updates the summary and posts the result."
        )
        assert cap.is_write is True
