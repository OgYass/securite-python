class Captcha:
    """Resolution du captcha."""

    def __init__(self, url):
        """Initialisation du captcha."""
        self.url = url
        self.image = ""
        self.value = ""

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        self.value = "FIXME"

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
