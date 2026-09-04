"""The BIP-353 review screen and the warning that precedes it when a proof does not verify.

Two things are worth testing here and they are different from the validator's own tests.

The first is layout. `TextArea` raises when its text will not fit the rect it is given, and the
name screen adds two lines to a 240x240 screen that was already carrying an amount and an address.
A screen that overflows does not fail quietly: it crashes the device the first time somebody
reviews a transaction, which is the worst possible moment. So every verdict is constructed against
a real in-memory canvas, with a long name, rather than trusted to fit.

The second is that the six failure states stay six. Nothing blocks signing here, which is a
deliberate decision, and it means the only thing standing between a user and a swapped recipient is
that the screen says something specific. A status added later with no wording and no colour would
silently inherit a default and undo that.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

# Must import test base before the Controller
from base import BaseTest
from ui_driver import make_test_renderer

from seedsigner.helpers import bip353
from seedsigner.helpers.bip353 import Status, Result


ALL_STATUSES = [getattr(Status, name) for name in dir(Status) if not name.startswith("_")]

# Long enough to wrap, and a realistic shape rather than a row of Xs
LONG_NAME = "averylongpaymentname@some-quite-long-domain.example.org"


def test_every_status_has_wording_and_a_colour():
    """A new status must not be able to reach the screen with no words attached to it"""
    from seedsigner.views.psbt_views import PSBTAddressDetailsView

    for status in ALL_STATUSES:
        assert status in PSBTAddressDetailsView.STATUS_TEXT, f"{status} has no wording"
        assert status in PSBTAddressDetailsView.STATUS_COLOR, f"{status} has no colour"


def test_only_a_verified_proof_is_shown_in_the_success_colour():
    """Green is the one signal the user reads at a glance, so nothing else may borrow it"""
    from seedsigner.gui.components import GUIConstants
    from seedsigner.views.psbt_views import PSBTAddressDetailsView

    for status, color in PSBTAddressDetailsView.STATUS_COLOR.items():
        if status == Status.VERIFIED:
            assert color == GUIConstants.SUCCESS_COLOR
        else:
            assert color != GUIConstants.SUCCESS_COLOR, f"{status} is coloured like a pass"


def test_a_failed_proof_never_reads_as_verified():
    from seedsigner.views.psbt_views import PSBTAddressDetailsView

    for status, text in PSBTAddressDetailsView.STATUS_TEXT.items():
        if status == Status.VERIFIED:
            continue
        assert "NOT VERIFIED" in text or text.isupper(), (
            f"{status} says {text!r}, which does not read as a failure")


class TestPaymentNameScreen(BaseTest):
    """Layout, against a real canvas rather than a mock that cannot overflow"""

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

    def _screen(self, **kwargs):
        from seedsigner.gui.screens.psbt_screens import PSBTAddressDetailsScreen
        from seedsigner.gui.screens.screen import ButtonOption

        defaults = dict(
            title="Will Send",
            button_data=[ButtonOption("Next")],
            address="bc1p5cyxnuxmeuwuvkwfem96l3xnvzxvsmz8lrzk3rgd9v3zmk9d8vzs4wcx2z",
            amount=10_000,
        )
        defaults.update(kwargs)
        return PSBTAddressDetailsScreen(**defaults)

    def test_an_output_with_no_proof_renders_exactly_as_before(self):
        screen = self._screen()
        assert screen.body_img is not None
        assert screen.body_img.height <= self.mock_renderer.canvas_height

    @pytest.mark.parametrize("status", ALL_STATUSES)
    def test_every_verdict_fits_on_the_screen(self, status):
        from seedsigner.views.psbt_views import PSBTAddressDetailsView

        screen = self._screen(
            payment_name=LONG_NAME,
            payment_name_status=PSBTAddressDetailsView.STATUS_TEXT[status],
            payment_name_color=PSBTAddressDetailsView.STATUS_COLOR[status],
        )
        assert screen.body_img is not None
        assert screen.body_img.height <= self.mock_renderer.canvas_height, (
            f"the {status} screen is {screen.body_img.height}px tall on a 240px screen")

    def test_a_huge_amount_alongside_a_long_name_still_fits(self):
        """21 million bitcoin renders wider than anything a test usually passes"""
        from seedsigner.views.psbt_views import PSBTAddressDetailsView

        screen = self._screen(
            amount=2_100_000_000_000_000,
            payment_name=LONG_NAME,
            payment_name_status=PSBTAddressDetailsView.STATUS_TEXT[Status.OUTPUT_MISMATCH],
            payment_name_color=PSBTAddressDetailsView.STATUS_COLOR[Status.OUTPUT_MISMATCH],
        )
        assert screen.body_img.height <= self.mock_renderer.canvas_height


class TestDeviceClock(BaseTest):
    """`now` must be None until the user has actually given the device a date"""

    def test_an_unscanned_device_reports_no_date(self):
        from seedsigner.views.psbt_views import PSBTAddressDetailsView

        view = PSBTAddressDetailsView.__new__(PSBTAddressDetailsView)
        view.controller = MagicMock(timecode_offset=None)
        assert view.device_now() is None

    def test_a_device_whose_clock_was_set_reports_its_own_clock(self):
        from seedsigner.views.psbt_views import PSBTAddressDetailsView

        view = PSBTAddressDetailsView.__new__(PSBTAddressDetailsView)
        view.controller = MagicMock(timecode_offset=0.0)
        assert abs(view.device_now() - time.time()) < 2

    def test_a_simulator_carrying_an_offset_reports_the_scanned_time(self):
        """The simulator cannot set the host clock, so it carries the difference instead"""
        from seedsigner.views.psbt_views import PSBTAddressDetailsView

        scanned = 1788400000
        view = PSBTAddressDetailsView.__new__(PSBTAddressDetailsView)
        view.controller = MagicMock(timecode_offset=scanned - time.time())
        assert abs(view.device_now() - scanned) < 2

    def test_the_psbts_own_timestamp_is_never_used_as_the_date(self):
        """psbt_source_time comes from the machine that made the PSBT and must not count

        If it did, one machine would supply both the proof and the date the proof is judged
        against, and could hand over a long-expired proof with a matching date.
        """
        from seedsigner.views.psbt_views import PSBTAddressDetailsView

        view = PSBTAddressDetailsView.__new__(PSBTAddressDetailsView)
        view.controller = MagicMock(timecode_offset=None, psbt_source_time=1788400000)
        assert view.device_now() is None


class TestVerdictLookup(BaseTest):
    """Reading a verdict off the parser, without going near a real PSBT"""

    def _view(self, names, offset=0.0):
        from seedsigner.views.psbt_views import PSBTAddressDetailsView

        view = PSBTAddressDetailsView.__new__(PSBTAddressDetailsView)
        view.controller = MagicMock(timecode_offset=offset)
        view.settings = MagicMock()
        view.settings.get_value.return_value = "main"
        parser = MagicMock(destination_payment_names=names)
        return view, parser

    def test_an_output_with_no_proof_has_no_verdict(self):
        view, parser = self._view([None])
        assert view.verified_payment_name(parser, 0) is None

    def test_a_parser_that_never_heard_of_payment_names_is_tolerated(self):
        """An older parsed PSBT in the back stack must not crash the review screen"""
        from seedsigner.views.psbt_views import PSBTAddressDetailsView

        view = PSBTAddressDetailsView.__new__(PSBTAddressDetailsView)
        view.controller = MagicMock(timecode_offset=0.0)
        parser = MagicMock(spec=[])
        assert view.verified_payment_name(parser, 0) is None

    def test_a_carried_proof_is_verified_with_the_devices_date(self):
        view, parser = self._view([{"hrn": "x@y.example", "chain": b"nonsense", "sp_data": None}])
        result = view.verified_payment_name(parser, 0)
        # Garbage in, a refusal out, and specifically not a crash
        assert isinstance(result, Result)
        assert result.status == Status.CHAIN_INVALID


class TestWarningViewOffersNoDeadEnd(BaseTest):
    """Every button on the warning screen must lead back into the review, not out of it

    This is a regression test for a bug that only showed up when the flow was driven end to end.
    The no-date screen offered "Scan date QR", which looked obviously right and was not: ScanView
    returns to the main menu when it finishes, nothing carries a half-finished PSBT review back,
    and there is no menu path to resume one. So the button set the clock and silently discarded the
    transaction the user was in the middle of approving.
    """

    def test_the_only_button_continues_the_review(self):
        from seedsigner.views.psbt_views import PSBTPaymentNameWarningView

        buttons = [v for k, v in vars(PSBTPaymentNameWarningView).items() if k.isupper()]
        assert len(buttons) == 1, f"expected one button option, found {len(buttons)}"
        assert buttons[0] is PSBTPaymentNameWarningView.CONTINUE

    def test_no_status_routes_away_from_the_psbt(self):
        """Whatever the verdict, accepting it must land back on the recipient screen"""
        import inspect
        import re

        from seedsigner.views.psbt_views import PSBTPaymentNameWarningView

        source = inspect.getsource(PSBTPaymentNameWarningView)
        assert "Destination(ScanView" not in source, (
            "the warning view routes to ScanView, which returns to the main menu and loses the "
            "PSBT review; it needs a return path before that button can exist")
        # The only destinations this view may produce are back, or on into the review.
        targets = set(re.findall(r"Destination\(\s*([A-Za-z_]+)", source))
        assert targets == {"BackStackView", "PSBTAddressDetailsView"}, (
            f"the warning view can route to {sorted(targets)}")


class TestWarningTextFits(BaseTest):
    """Each warning has to fit a 240x240 screen with a headline and a button on it

    Found by looking at one: the no-date warning ran past the bottom and its last line was drawn
    underneath the button, so the sentence telling the user what to do was the part they could not
    read. TextArea does not raise for this. It lays the text out, logs "Text cannot fit in target
    rect", and carries on, which is why nothing failed until somebody looked at a screenshot.

    That log line is the component's own verdict, so the test listens for it rather than
    re-deriving the geometry and getting it subtly wrong.
    """

    NAME = "rob@silentpayments.net"

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

    def _texts(self):
        """The real strings the view builds, with a realistic name substituted in"""
        return {
            "mismatch":
                "%s: the proof covers a different recipient. This pays someone else." % self.NAME,
            "no-clock":
                "%s: the proof is unchecked. Scan a date QR from a second screen." % self.NAME,
            "expired":
                "%s: the proof is outside its validity window." % self.NAME,
            "failed":
                "%s could not be verified: the DNSSEC chain did not validate" % self.NAME,
        }

    @pytest.mark.parametrize("case", ["mismatch", "no-clock", "expired", "failed"])
    def test_the_warning_text_fits_its_screen(self, case, caplog):
        import logging

        from seedsigner.gui.screens.screen import ButtonOption, WarningScreen

        with caplog.at_level(logging.WARNING, logger="seedsigner.gui.components"):
            WarningScreen(
                title="Not verified",
                status_headline="Check this",
                text=self._texts()[case],
                show_back_button=True,
                button_data=[ButtonOption("I accept the risk")],
            )

        overflow = [r.getMessage() for r in caplog.records if "cannot fit" in r.getMessage()]
        assert not overflow, (
            f"the {case} warning does not fit its screen: {overflow[0]}; "
            f"its last line would be drawn under the button")
