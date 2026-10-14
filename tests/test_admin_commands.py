"""Admin account commands: list-users, create-user (invitation), disable-user."""
import re

from pastry import cli
from tests.conftest import USERNAME
from tests.test_setup_admin import Prompts


def _ctx(settings, passwords=(), text=()):
    prompts = Prompts(list(passwords), list(text))
    return cli.Context(settings=settings, prompt_password=prompts.password, prompt_text=prompts.input)


def test_list_users_shows_the_owner(provisioned, capsys):
    assert cli.main(["admin", "list-users"], _ctx(provisioned)) == 0
    out = capsys.readouterr().out
    assert USERNAME in out and "owner" in out and "active" in out


def test_create_user_prints_a_single_use_invitation(provisioned, capsys):
    assert cli.main(["admin", "create-user"], _ctx(provisioned, text=["alice"])) == 0
    out = capsys.readouterr().out
    assert re.search(r"/invite/[A-Za-z0-9_-]{20,}", out)
    assert "works once" in out and "never sees it" in out


def test_created_invitation_appears_in_list(provisioned, capsys):
    cli.main(["admin", "create-user"], _ctx(provisioned, text=["alice"]))
    capsys.readouterr()
    cli.main(["admin", "list-users"], _ctx(provisioned))
    assert "Pending invitations: 1" in capsys.readouterr().out


def test_create_user_rejects_the_owners_name(provisioned, capsys):
    assert cli.main(["admin", "create-user"], _ctx(provisioned, text=[USERNAME])) == 1
    assert "already taken" in capsys.readouterr().err


def test_disable_user_refuses_unknown_and_owner(provisioned, capsys):
    assert cli.main(["admin", "disable-user", "nobody"], _ctx(provisioned)) == 1
    assert cli.main(["admin", "disable-user", USERNAME], _ctx(provisioned)) == 1
    assert "owner account cannot be disabled" in capsys.readouterr().err
