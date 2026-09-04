"""Driving a MuSig2 spend through the screens, both rounds.

The transaction is the captured one from tests/data/musig2_psbts.json, a 2-of-3
whose key path pair is this seed and Bitcoin Core. Round one produces no
signature at all, which is the point of the first test: the flow has to end
somewhere that says so, rather than at the signing-error screen it would reach
if MuSig2 were counted like an ordinary signature.
"""

import json
import os

from base import FlowTest, FlowStep

from seedsigner.models.seed import Seed
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.views.view import MainMenuView
from seedsigner.views import psbt_views, scan_views

FIXTURE = os.path.join(os.path.dirname(__file__), "data", "musig2_psbts.json")


class TestMusig2Flows(FlowTest):

    def setup_method(self):
        super().setup_method()
        with open(FIXTURE) as f:
            self.data = json.load(f)
        Settings.get_instance().set_value(
            SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)
        self.seed = Seed(mnemonic=self.data["mnemonics"]["B"].split())
        self.controller.storage.seeds.append(self.seed)

    def _sequence(self, psbt_b64, final_view):
        def load_psbt(view: scan_views.ScanView):
            view.decoder.add_data(psbt_b64)

        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt),
            # button_data_selection is checked for truthiness in base.py, so index
            # zero has to be passed as a return value instead.
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTNoChangeWarningView, screen_return_value=0),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, screen_return_value=0),
            FlowStep(psbt_views.PSBTFinalizeView,
                     button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTMusig2RoundView),
            FlowStep(final_view),
        ]

    def test_round_one_publishes_a_nonce_and_says_so(self):
        """No signature exists yet, and the flow must not treat that as failure."""
        self.run_sequence(self._sequence(self.data["psbt_round_one"],
                                         psbt_views.PSBTSignedQRDisplayView))

        from seedsigner.helpers import musig2_psbt
        psbt = self.controller.psbt
        role = next(r for r in musig2_psbt.roles_for_root(psbt, self.seed.get_root(
            SettingsConstants.REGTEST)) if r.is_keypath)
        nonces = musig2_psbt.scope_fields(psbt.inputs[role.input_index],
                                          musig2_psbt.FIELD_PUBNONCE)
        assert role.my_pubkey + role.agg_id in nonces
        assert not musig2_psbt.has_partial_sig(psbt, role)
        assert len(self.controller.musig2_session) == 1

    def test_round_two_signs(self):
        """The same walk again, on a transaction that already carries both
        nonces. The secret nonce has to come from the session the first round
        left behind, which is why this drives the flow twice rather than
        starting from the second PSBT."""
        self.run_sequence(self._sequence(self.data["psbt_round_one"],
                                         psbt_views.PSBTSignedQRDisplayView))
        assert len(self.controller.musig2_session) == 1

        self.run_sequence(self._sequence(self.data["psbt_both_nonces"],
                                         psbt_views.PSBTSignedQRDisplayView))

        from seedsigner.helpers import musig2_psbt
        psbt = self.controller.psbt
        role = next(r for r in musig2_psbt.roles_for_root(psbt, self.seed.get_root(
            SettingsConstants.REGTEST)) if r.is_keypath)
        assert musig2_psbt.has_partial_sig(psbt, role)
        assert len(self.controller.musig2_session) == 0, \
            "the secret nonce outlived the signature"


class TestMusig2SilentPaymentFlows(FlowTest):
    """The round before the nonces, on screen.

    A silent payment send arrives as PSBTv2 with an output that has no script
    yet. The walk to the sign screen is the ordinary one, the review shows the
    sp1 address the send is aimed at, and what comes out is a share and a
    proof, with no nonce and no signature and a screen that says so.
    """

    def setup_method(self):
        super().setup_method()
        with open(FIXTURE) as f:
            self.data = json.load(f)
        settings = Settings.get_instance()
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)
        settings.set_value(SettingsConstants.SETTING__SILENT_PAYMENTS,
                           SettingsConstants.OPTION__ENABLED)
        self.seed = Seed(mnemonic=self.data["mnemonics"]["B"].split())
        self.controller.storage.seeds.append(self.seed)

    def test_round_zero_hands_out_a_share_and_no_nonce(self):
        from seedsigner.helpers import silent_payments
        if not silent_payments.is_available():
            import pytest
            pytest.skip("installed embit has no BIP-352 support")

        from embit import bip39
        from test_musig2_sp import silent_send
        from seedsigner.helpers import musig2_psbt, musig2_sp

        scan, spend = silent_payments.derive_keys(
            bip39.mnemonic_to_seed(self.data["mnemonics"]["C"]), SettingsConstants.REGTEST)
        # Framed the way a coordinator sends it. The bare-base64 detector parses
        # with stock PSBT, which cannot read a v2 with a scriptless output, so
        # that path is not the one a silent payment send arrives by.
        psbt_b64 = "p1of1 " + silent_send(self.data, (scan, spend)).to_string()

        def load_psbt(view: scan_views.ScanView):
            view.decoder.add_data(psbt_b64)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt),
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTNoChangeWarningView, screen_return_value=0),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, screen_return_value=0),
            FlowStep(psbt_views.PSBTFinalizeView,
                     button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTMusig2RoundView),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
        ])

        psbt = self.controller.psbt
        parser = self.controller.psbt_parser
        assert parser.destination_addresses[0].startswith("tsp1"), \
            "the review must show the silent payment address, not a placeholder"

        role = next(r for r in musig2_psbt.roles_for_root(
            psbt, self.seed.get_root(SettingsConstants.REGTEST)) if r.is_keypath)
        scan_key = musig2_sp.scan_keys(psbt)[0]
        assert musig2_sp.has_share(psbt, role, scan_key)
        assert not musig2_psbt.scope_fields(psbt.inputs[role.input_index],
                                            musig2_psbt.FIELD_PUBNONCE)
        assert len(self.controller.musig2_session) == 0
        assert musig2_sp.scripts_missing(psbt), "the device must not write the script itself"
