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
