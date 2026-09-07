"""
    The MuSig2 card screens have to fit a 240x240 panel.

    TextArea does not raise when its text overruns. It lays it out, logs "Text cannot
    fit in target rect", and carries on, so nothing fails and the flow tests still pass
    while the panel receives a sentence cut off mid-clause.

    That is not hypothetical here. The offer screen shipped clipping its own last line,
    "power off in between", which is the entire reason to press the button. It was found
    by rendering it through the real display driver, not by reading it. The cause was
    two buttons rather than long text: the same screen with one button fits.

    These listen for the component's own verdict rather than re-deriving the geometry.
"""
from unittest.mock import patch

import pytest

# Must import test base before the Controller
from base import BaseTest
from ui_driver import make_test_renderer


class TestMusig2CardScreensFit(BaseTest):

    def setup_method(self):
        super().setup_method()
        from seedsigner.gui.renderer import Renderer

        self.mock_renderer = make_test_renderer()
        self.renderer_patch = patch.object(
            Renderer, "get_instance", return_value=self.mock_renderer)
        self.renderer_patch.start()

    def teardown_method(self):
        self.renderer_patch.stop()
        super().teardown_method()

    def _no_overflow(self, caplog, what):
        overflow = [r.getMessage() for r in caplog.records if "cannot fit" in r.getMessage()]
        assert not overflow, (
            f"{what} does not fit its screen: {overflow[0]}; "
            f"the part it loses is drawn under the buttons")

    def test_the_offer_fits_with_both_its_buttons(self, caplog):
        """Two buttons take about a line of height, which is what clipped it before."""
        import logging

        from seedsigner.gui.components import GUIConstants
        from seedsigner.gui.screens.screen import LargeIconStatusScreen
        from seedsigner.views.psbt_views import PSBTMusig2CardOfferView

        with caplog.at_level(logging.WARNING, logger="seedsigner.gui.components"):
            LargeIconStatusScreen(
                title="MuSig2",
                status_icon_size=0,
                status_headline="Card Signing",
                status_color=GUIConstants.BODY_FONT_COLOR,
                text="A card holds this signing so the device can be switched off.",
                show_back_button=True,
                button_data=[PSBTMusig2CardOfferView.USE_CARD,
                             PSBTMusig2CardOfferView.KEEP_DEVICE_ON],
            )

        self._no_overflow(caplog, "the card offer")

    def test_the_wrong_card_warning_fits(self, caplog):
        import logging

        from seedsigner.gui.screens.screen import ButtonOption, WarningScreen

        with caplog.at_level(logging.WARNING, logger="seedsigner.gui.components"):
            WarningScreen(
                status_headline="Wrong Card",
                text="That card is not holding this seed. Signing continues without it.",
                button_data=[ButtonOption("Continue")],
            )

        self._no_overflow(caplog, "the wrong-card warning")

    def test_both_round_screen_texts_fit(self, caplog):
        """The round screen says where the nonce is, and the card sentence is the
        longer of the two. Four lines fit; a fifth would clip."""
        import logging

        from seedsigner.gui.screens.screen import LargeIconStatusScreen, ButtonOption

        for text in (
            "Not signed yet. Send this back, then scan it again. Your card is "
            "holding it, so you can switch off.",
            "Not signed yet. Send this back, then scan it again. Keep this device on.",
        ):
            with caplog.at_level(logging.WARNING, logger="seedsigner.gui.components"):
                LargeIconStatusScreen(
                    title="MuSig2 2 of 3",
                    status_headline="Step 1 of 2",
                    text=text,
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
            self._no_overflow(caplog, "the round screen")
