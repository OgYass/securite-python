from tp3.utils.args import Args


def test_args_target_has_no_trailing_slash():
    # Args est construit au chargement du module (valeurs par défaut de argparse).
    assert not Args.target.endswith("/")
    assert Args.target.startswith("http")


def test_args_verbose_is_bool():
    assert isinstance(Args.verbose, bool)
