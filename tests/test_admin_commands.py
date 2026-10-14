"""Admin account commands. Multi-user commands must refuse rather than pretend to work."""
from pastry import cli
from tests.conftest import USERNAME
from tests.test_setup_admin import Prompts


def _ctx(settings, passwords=(), text=()):
    prompts = Prompts(list(passwords), list(text))
    return cli.Context(settings=settings, prompt_password=prompts.password, prompt_text=prompts.input)


def test_list_users_shows_only_the_owner(provisioned, capsys):
    assert cli.main(["admin", "list-users"], _ctx(provisioned)) == 0
    out = capsys.readouterr().out
    assert f"{USERNAME}  (owner)" in out
    assert "disabled in this version" in out


def test_create_user_refuses_and_changes_nothing(provisioned, capsys):
    before = provisioned.auth_path.read_bytes()
    assert cli.main(["admin", "create-user"], _ctx(provisioned)) == 2
    assert "not available in Pastry 1.1" in capsys.readouterr().err
    assert provisioned.auth_path.read_bytes() == before


def test_disable_user_refuses_and_changes_nothing(provisioned, capsys):
    before = provisioned.auth_path.read_bytes()
    assert cli.main(["admin", "disable-user"], _ctx(provisioned)) == 2
    assert provisioned.auth_path.read_bytes() == before
