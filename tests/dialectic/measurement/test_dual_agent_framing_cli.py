from scripts.run_session_084 import main


def test_cli_rejects_cost_ceiling_over_hard_cap(capsys):
    rc = main(["--provider", "anthropic", "--cost-ceiling", "9999"])
    assert rc == 2
    assert "hard cap" in capsys.readouterr().err
