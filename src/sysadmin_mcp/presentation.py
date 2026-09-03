"""Raw-first presentation and safe summary boundary for diagnostic results."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from .models import CommandResult


class SummaryProvider(Protocol):
    """Replaceable summary boundary; providers receive data, never capabilities."""

    async def summarize(self, capability: str, results: Sequence[CommandResult]) -> str: ...


class SafeSummaryProvider:
    """Content-blind default summary which cannot follow instructions in output."""

    async def summarize(self, capability: str, results: Sequence[CommandResult]) -> str:
        del capability
        line_count = sum(len(result.stdout.splitlines()) for result in results)
        failures = [result.exit_status for result in results if result.exit_status != 0]
        notices: list[str] = []
        if failures:
            statuses = ", ".join(str(status) for status in failures)
            notices.append(f"The diagnostic command failed with exit status {statuses}.")
        else:
            command_word = "commands" if len(results) != 1 else "command"
            notices.append(
                f"The read-only diagnostic {command_word} completed successfully and returned "
                f"{line_count} stdout line{'s' if line_count != 1 else ''}."
            )
        if any(result.truncated for result in results):
            notices.append("Some raw output was truncated at the configured safety limit.")
        elif any(result.stderr for result in results):
            notices.append("The command also returned diagnostic text on stderr.")
        return " ".join(notices)


@dataclass(frozen=True)
class Presentation:
    summary: str
    display_markdown: str


class DiagnosticPresenter:
    """Render verbatim raw streams first, followed by a short summary."""

    def __init__(self, summary_provider: SummaryProvider | None = None) -> None:
        self._summary_provider = summary_provider or SafeSummaryProvider()

    async def present(
        self, capability: str, results: Sequence[CommandResult]
    ) -> Presentation:
        summary = (await self._summary_provider.summarize(capability, results)).strip()
        if not summary:
            raise ValueError("summary provider returned an empty summary")
        return Presentation(summary=summary, display_markdown=self._render(results, summary))

    @classmethod
    def _render(cls, results: Sequence[CommandResult], summary: str) -> str:
        sections = ["## Raw output"]
        for index, result in enumerate(results, start=1):
            if len(results) > 1:
                sections.append(f"### Command {index}: `{result.command[0]}`")
            sections.extend(cls._stream_section("stdout", result.stdout))
            if result.stderr:
                sections.extend(cls._stream_section("stderr", result.stderr))
        sections.extend(("## Summary", summary))
        return "\n\n".join(sections)

    @staticmethod
    def _stream_section(label: str, value: str) -> list[str]:
        longest_run = 0
        current_run = 0
        for character in value:
            if character == "`":
                current_run += 1
                longest_run = max(longest_run, current_run)
            else:
                current_run = 0
        fence = "`" * max(3, longest_run + 1)
        return [f"#### {label}", f"{fence}text\n{value}\n{fence}"]
