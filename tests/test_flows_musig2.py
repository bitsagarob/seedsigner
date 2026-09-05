"""
    The MuSig2 rounds on screen. Round one ends on a screen that says nothing is signed
    yet; a malformed arrangement ends on a refusal, not a crash.
"""
import json
import os

import pytest
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
        Settings.get_instance().set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)
        Settings.get_instance().set_value(SettingsConstants.SETTING__SILENT_PAYMENTS,
                                          SettingsConstants.OPTION__ENABLED)
        self.seed = Seed(mnemonic=self.data["mnemonics"]["B"].split())
        self.controller.storage.seeds.append(self.seed)

    def _walk(self, psbt_b64, tail):
        def load_psbt(view: scan_views.ScanView):
            view.decoder.add_data(psbt_b64)

        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt),
            # index zero has to be a return value; button_data_selection is truthiness-checked
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTNoChangeWarningView, screen_return_value=0),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, screen_return_value=0),
            FlowStep(psbt_views.PSBTFinalizeView,
                     button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
        ] + tail

    def _role(self):
        from seedsigner.helpers import musig2_psbt
        return musig2_psbt.roles(self.controller.psbt, self.seed.get_root(SettingsConstants.REGTEST))[0][0]

    def _without_other_nonces(self):
        from embit.psbt import PSBT
        from seedsigner.helpers import musig2_psbt
        psbt = PSBT.from_string(self.data["psbt_round_one"])
        for key in [k for k in psbt.inputs[0].unknown if k[0] == musig2_psbt.PSBT_IN_MUSIG2_PUB_NONCE]:
            del psbt.inputs[0].unknown[key]
        return psbt.to_string()

    def test_round_one_publishes_a_nonce_and_says_so(self):
        from seedsigner.helpers import musig2_psbt
        self.run_sequence(self._walk(self._without_other_nonces(), [
            FlowStep(psbt_views.PSBTMusig2RoundView),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
        ]))
        role = self._role()
        assert musig2_psbt.pubnonces(self.controller.psbt, role).count(None) == 1
        assert musig2_psbt.partial_sig(self.controller.psbt, role) is None
        assert len(self.controller.musig2_session) == 1

    def test_round_two_signs(self):
        from seedsigner.helpers import musig2_psbt
        self.run_sequence(self._walk(self._without_other_nonces(), [
            FlowStep(psbt_views.PSBTMusig2RoundView),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
        ]))
        self.run_sequence(self._walk(self.data["psbt_round_one"], [
            FlowStep(psbt_views.PSBTMusig2RoundView),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
        ]))
        assert musig2_psbt.partial_sig(self.controller.psbt, self._role()) is not None
        assert len(self.controller.musig2_session) == 0

    def test_a_malformed_arrangement_is_refused_on_screen(self):
        from embit.psbt import PSBT
        from seedsigner.helpers import musig2_psbt
        psbt = PSBT.from_string(self.data["psbt_round_one"])
        scope = psbt.inputs[0]
        key = next(k for k in scope.unknown if k[0] == musig2_psbt.PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS)
        scope.unknown[key] = scope.unknown[key][:65]
        self.run_sequence(self._walk(psbt.to_string(), [
            FlowStep(psbt_views.PSBTMusig2RoundView, screen_return_value=0),
            FlowStep(MainMenuView),
        ]))

    def test_round_zero_of_a_silent_payment_hands_out_a_share(self):
        from seedsigner.helpers import silent_payments, musig2_psbt
        if not silent_payments.is_available():
            pytest.skip("installed embit has no BIP-352 support")
        from embit import bip39
        from test_musig2_sp import silent_send

        recipient = silent_payments.derive_keys(
            bip39.mnemonic_to_seed(self.data["mnemonics"]["C"]), SettingsConstants.REGTEST)
        # Framed as a coordinator sends it; the bare-base64 detector cannot read a v2 send
        self.run_sequence(self._walk("p1of1 " + silent_send(self.data, recipient).to_string(), [
            FlowStep(psbt_views.PSBTMusig2RoundView),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
        ]))
        psbt = self.controller.psbt
        assert self.controller.psbt_parser.destination_addresses[0].startswith("tsp1")
        role = self._role()
        assert musig2_psbt.has_share(psbt, role, musig2_psbt.sp_scan_keys(psbt)[0])
        assert musig2_psbt.pubnonces(psbt, role).count(None) == 2
        assert musig2_psbt.sp_scripts_missing(psbt)
        assert len(self.controller.musig2_session) == 0
