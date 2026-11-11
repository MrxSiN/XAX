from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_agent_instruction_files_are_one_policy():
    """AGENT.md and CLAUDE.md are the same instructions for different tools; a rule added to one belongs in both."""
    assert (ROOT / "AGENT.md").read_bytes() == (ROOT / "CLAUDE.md").read_bytes()
