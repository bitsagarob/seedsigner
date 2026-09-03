"""BIP-352 silent payments, checked against the vectors published on SeedSigner#769.

These are earthdiver's vectors from the #769 review thread, so passing them means
this fork and that pull request agree on what a seed means. They are published
test seeds and hold no coins.

The scan key is checked as well as the address, because the two are easy to
confuse in code and catastrophic to confuse in a UI: one is public, the other
contains a private key.
"""
from unittest.mock import patch

import pytest

from base import BaseTest, FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.views import seed_views

from seedsigner.helpers import silent_payments
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants


# Published on SeedSigner#769. No coins.
VECTORS = [
    dict(
        mnemonic="initial tilt corn easily leave weather strategy return topple gesture sad day",
        network=SettingsConstants.TESTNET,
        payment_address="tsp1qqfvn9pmvmz0ewpnp7w302lxqmnue2kgtpne2p38nuunun883sw36yq48ny7n2jl0nx9ljhmdnrgvpee6aufmg9wfvqfcr6c02at6r4u4xsegph7a",
        scan_key="tspscan1q09zrmaz09cdzs5jxm552qpv3f2gxd9vxhs0yady09jdd6aqt5e7s9fue8565hmue30u47mvc6rqwwwh0zw6ptjtqzwq7kr6h27sa09f5g6x977",
    ),
    dict(
        mnemonic="tongue vanish post gentle fever figure kangaroo select infant blur phrase relief",
        network=SettingsConstants.MAINNET,
        payment_address="sp1qq2c4jvrju33tmm9ll0560vm0rflfxkhd8zj74pka8s53dyaztzwlqqhrkuv0ut7wjv08kdq26t4twguxdcd9m35p6z4n784wyg3efwruevxty23x",
        scan_key="spscan1qnd95fpg2587jn73qg98pq8uk20y09v5c20u0e4kynsc4m2qmkrrs9cahrrlzln5nreangzkja2mj8pnwrfwudqws4vl3at3zyw2tslxtryq7pn",
    ),
    dict(
        mnemonic="index today witness obscure ugly curtain symbol pumpkin pelican child maple struggle arctic water tiny pizza harbor below violin eight tennis frost clown hood",
        network=SettingsConstants.TESTNET,
        payment_address="tsp1qqvdcq76j5kul4s6t52d07ssq8l96k49jur0kytua36k9qzj4m5xyxq5j2v4hc8njddv9xtnhly7hyv2agt28fypqn29q8mw3fjjlz00vvv824hd6",
        scan_key="tspscan1q0z4tkwaar4ww77qgesalgzw0c40q89zh7p7hmp3qn73yrdw9jpvs9yjn9d7puunttpfjuale84erzh2z636fqgy63gp7m52v5hcnmmrrlrxnur",
    ),
    dict(
        mnemonic="fold cotton pipe robust eagle rabbit coach average orient utility minor absurd fine claim artist rabbit kingdom original lobster cruise march city vibrant resemble",
        network=SettingsConstants.MAINNET,
        payment_address="sp1qq25f3laffnhpl69ytaxzz5gjnkrm2a2jr3mfz0ff6wuesg4j9e5lcqjj5qq7fy0t0wy9qvty7l7wk8vnmyxpxeq5ae0lmmzlgwnutg8945k2w7lh",
        scan_key="spscan1q79q4zljllyehszny72w5zfptzpxnp96esg0n2fwecgzd2v7fr6fsy54qq8jfr6mm3pgrze8hln43my7epsfkg98wtl77ch6r5lz6pedd2jcnxk",
    ),
]


class TestSilentPayments(BaseTest):

    @pytest.mark.parametrize("vector", VECTORS)
    def test_payment_address_matches_published_vector(self, vector):
        seed = Seed(mnemonic=vector["mnemonic"].split())
        assert silent_payments.payment_address(seed.seed_bytes, vector["network"]) == vector["payment_address"]


    @pytest.mark.parametrize("vector", VECTORS)
    def test_scan_key_matches_published_vector(self, vector):
        seed = Seed(mnemonic=vector["mnemonic"].split())
        assert silent_payments.scan_key(seed.seed_bytes, vector["network"]) == vector["scan_key"]


    @pytest.mark.parametrize("vector", VECTORS)
    def test_the_address_and_the_scan_key_are_never_the_same_string(self, vector):
        """A UI that showed one where it meant the other would leak the scan key."""
        seed = Seed(mnemonic=vector["mnemonic"].split())
        address = silent_payments.payment_address(seed.seed_bytes, vector["network"])
        watch = silent_payments.scan_key(seed.seed_bytes, vector["network"])
        assert address != watch
        assert address.startswith(("sp1", "tsp1"))
        assert watch.startswith(("spscan1", "tspscan1"))


    def test_coin_type_follows_slip44(self):
        assert silent_payments.coin_type_for(SettingsConstants.MAINNET) == 0
        assert silent_payments.coin_type_for(SettingsConstants.TESTNET) == 1
        # Regtest is not a separate SLIP-44 coin type; it shares testnet's.
        assert silent_payments.coin_type_for(SettingsConstants.REGTEST) == 1


    def test_mainnet_and_testnet_disagree_for_the_same_seed(self):
        """Different coin type, so the same words must not produce the same address."""
        seed = Seed(mnemonic=VECTORS[0]["mnemonic"].split())
        assert (silent_payments.payment_address(seed.seed_bytes, SettingsConstants.MAINNET)
                != silent_payments.payment_address(seed.seed_bytes, SettingsConstants.TESTNET))


    @pytest.mark.parametrize("vector", VECTORS)
    def test_the_descriptor_carries_the_origin_a_coordinator_needs(self, vector):
        """Sparrow wraps what it scans in sp(...), so we must NOT return sp(...)."""
        seed = Seed(mnemonic=vector["mnemonic"].split())
        fingerprint = seed.get_fingerprint(vector["network"])
        descriptor = silent_payments.scan_key_descriptor(seed.seed_bytes, vector["network"], fingerprint)

        coin = silent_payments.coin_type_for(vector["network"])
        assert descriptor == "[%s/352h/%dh/0h]%s" % (fingerprint, coin, vector["scan_key"])
        assert not descriptor.startswith("sp(")
        assert "#" not in descriptor  # no checksum


    @pytest.mark.parametrize("vector", VECTORS)
    def test_derivation_uses_the_bip352_paths(self, vector):
        """scan m/352h/coin/0h/1h/0 and spend m/352h/coin/0h/0h/0, per BIP-352."""
        from embit import bip32
        from embit.networks import NETWORKS
        from seedsigner.helpers.embit_utils import get_embit_network_name

        seed = Seed(mnemonic=vector["mnemonic"].split())
        coin = silent_payments.coin_type_for(vector["network"])
        root = bip32.HDKey.from_seed(
            seed.seed_bytes,
            version=NETWORKS[get_embit_network_name(vector["network"])]["xprv"],
        )
        scan, spend = silent_payments.derive_keys(seed.seed_bytes, vector["network"])
        assert scan.secret == root.derive("m/352h/%dh/0h/1h/0" % coin).key.secret
        assert spend.secret == root.derive("m/352h/%dh/0h/0h/0" % coin).key.secret
        # The two keys must never coincide; scan is a viewing key, spend moves money.
        assert scan.secret != spend.secret


class TestSilentPaymentsFlows(FlowTest):
    """The menu path, and the two things it can do."""

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(SettingsConstants.SETTING__SILENT_PAYMENTS, SettingsConstants.OPTION__ENABLED)
        self.controller.storage.set_pending_seed(Seed(mnemonic=VECTORS[0]["mnemonic"].split()))
        self.controller.storage.finalize_pending_seed()


    def test_the_entry_is_hidden_until_the_owner_enables_it(self):
        """Off by default, so it must not appear in SeedOptionsView unless switched on."""
        self.settings.set_value(SettingsConstants.SETTING__SILENT_PAYMENTS, SettingsConstants.OPTION__DISABLED)
        view = seed_views.SeedOptionsView(seed=self.controller.storage.seeds[0])
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_screen:
            view.run()
        assert seed_views.SeedOptionsView.SILENT_PAYMENTS not in mock_screen.call_args.kwargs["button_data"]


    def test_the_entry_appears_once_enabled(self):
        view = seed_views.SeedOptionsView(seed=self.controller.storage.seeds[0])
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_screen:
            view.run()
        assert seed_views.SeedOptionsView.SILENT_PAYMENTS in mock_screen.call_args.kwargs["button_data"]


    def test_show_address_flow(self):
        """Seeds > seed > Silent payments > Show address > QR, and back to the menu."""
        self.run_sequence([
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SILENT_PAYMENTS),
            FlowStep(seed_views.SeedSilentPaymentsOptionsView, button_data_selection=seed_views.SeedSilentPaymentsOptionsView.SHOW_ADDRESS),
            FlowStep(seed_views.SeedSilentPaymentsAddressView, button_data_selection=seed_views.SeedSilentPaymentsAddressView.SHOW_QR),
            FlowStep(seed_views.SeedSilentPaymentsAddressQRView),
            FlowStep(seed_views.SeedSilentPaymentsOptionsView),
        ], initial_destination_view_args=dict(seed=self.controller.storage.seeds[0]))


    def test_connect_to_sparrow_warns_before_the_scan_key_leaves(self):
        """The privacy warning is not optional unless the owner turned warnings off."""
        self.settings.set_value(SettingsConstants.SETTING__PRIVACY_WARNINGS, SettingsConstants.OPTION__ENABLED)
        self.run_sequence([
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SILENT_PAYMENTS),
            FlowStep(seed_views.SeedSilentPaymentsOptionsView, button_data_selection=seed_views.SeedSilentPaymentsOptionsView.CONNECT_SPARROW),
            FlowStep(seed_views.SeedSilentPaymentsConnectWarningView, screen_return_value=0),
            FlowStep(seed_views.SeedSilentPaymentsConnectAddressView, button_data_selection=seed_views.SeedSilentPaymentsConnectAddressView.SCAN_IN_SPARROW),
            FlowStep(seed_views.SeedSilentPaymentsConnectQRView),
            FlowStep(seed_views.SeedSilentPaymentsOptionsView),
        ], initial_destination_view_args=dict(seed=self.controller.storage.seeds[0]))


    def test_the_warning_is_skipped_when_privacy_warnings_are_off(self):
        self.settings.set_value(SettingsConstants.SETTING__PRIVACY_WARNINGS, SettingsConstants.OPTION__DISABLED)
        self.run_sequence([
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SILENT_PAYMENTS),
            FlowStep(seed_views.SeedSilentPaymentsOptionsView, button_data_selection=seed_views.SeedSilentPaymentsOptionsView.CONNECT_SPARROW),
            FlowStep(seed_views.SeedSilentPaymentsConnectWarningView, is_redirect=True),
            FlowStep(seed_views.SeedSilentPaymentsConnectAddressView, button_data_selection=seed_views.SeedSilentPaymentsConnectAddressView.SCAN_IN_SPARROW),
            FlowStep(seed_views.SeedSilentPaymentsConnectQRView),
            FlowStep(seed_views.SeedSilentPaymentsOptionsView),
        ], initial_destination_view_args=dict(seed=self.controller.storage.seeds[0]))


    def test_the_connect_qr_is_the_scan_key_and_the_screen_before_it_is_not(self):
        """The QR carries a private key; the screen before it must show the public address.

        Getting these two the wrong way round would print the scan key on screen
        as though it were an address, which is the worst single bug this feature
        could have.
        """
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        seed = self.controller.storage.seeds[0]

        address_view = seed_views.SeedSilentPaymentsConnectAddressView(seed=self.controller.storage.seeds[0])
        qr_view = seed_views.SeedSilentPaymentsConnectQRView(seed=self.controller.storage.seeds[0])

        assert address_view.payment_address == silent_payments.payment_address(seed.seed_bytes, network)
        assert address_view.payment_address.startswith(("sp1", "tsp1"))
        assert silent_payments.scan_key(seed.seed_bytes, network) in qr_view.descriptor
        assert address_view.payment_address not in qr_view.descriptor


class TestSilentPaymentsPSBT(BaseTest):
    """BIP-375 sends, checked against transactions that are actually on a chain.

    The fixtures in tests/data/silent_payments_psbts.json were recorded from real
    Bitsaga Signet transactions, so a regression here means the device would now
    produce something different from bytes a node already accepted.
    """

    @classmethod
    def setup_class(cls):
        # BaseTest.setup_class builds the mocked hardware every test needs, so
        # extend it rather than replacing it.
        super().setup_class()
        import json
        from pathlib import Path
        cls.fixtures = json.loads(
            (Path(__file__).parent / "data" / "silent_payments_psbts.json").read_text()
        )


    def setup_method(self):
        super().setup_method()
        self.settings.set_value(SettingsConstants.SETTING__SILENT_PAYMENTS, SettingsConstants.OPTION__ENABLED)


    def _signing_root(self, mnemonic, network=SettingsConstants.TESTNET):
        from embit import bip32, bip39
        from embit.networks import NETWORKS
        from seedsigner.helpers.embit_utils import get_embit_network_name
        return bip32.HDKey.from_seed(
            bip39.mnemonic_to_seed(mnemonic),
            version=NETWORKS[get_embit_network_name(network)]["xprv"],
        )


    def test_stock_psbt_cannot_even_parse_a_send(self):
        """Why the hook exists at all: PSBTv2 has no PSBT_OUT_SCRIPT to find."""
        from base64 import b64decode
        from embit.psbt import PSBT
        import pytest as _pytest

        raw = b64decode(self.fixtures["send"]["unsigned_psbt"])
        with _pytest.raises(Exception):
            PSBT.parse(raw)


    def test_decode_qr_routes_a_send_to_the_silent_payments_parser(self):
        from base64 import b64decode
        from embit.silent_payments.psbt import SilentPaymentsPSBT
        from seedsigner.models.decode_qr import DecodeQR

        raw = b64decode(self.fixtures["send"]["unsigned_psbt"])
        parsed = DecodeQR._parse_silent_payments_psbt(raw)
        assert isinstance(parsed, SilentPaymentsPSBT)
        assert parsed.has_sp_outputs


    @pytest.mark.parametrize("fixture_name", [
        "SINGLE_SIG_NATIVE_SEGWIT_1_INPUT",
        "SINGLE_SIG_NESTED_SEGWIT_1_INPUT",
        "SINGLE_SIG_TAPROOT_1_INPUT",
    ])
    def test_an_ordinary_psbt_is_left_to_the_stock_parser(self, fixture_name):
        """The hook must not take over every transaction, only silent payments.

        Taproot matters most here: an SP spend is a taproot input too, so a hook
        that keyed off script type alone would swallow every ordinary taproot
        transaction on the device.
        """
        from base64 import b64decode
        from seedsigner.models.decode_qr import DecodeQR
        from psbt_testing_util import PSBTTestData

        raw = b64decode(getattr(PSBTTestData, fixture_name))
        assert DecodeQR._parse_silent_payments_psbt(raw) is None


    def test_the_hook_is_inert_when_the_setting_is_off(self):
        from base64 import b64decode
        from seedsigner.models.decode_qr import DecodeQR

        self.settings.set_value(SettingsConstants.SETTING__SILENT_PAYMENTS, SettingsConstants.OPTION__DISABLED)
        raw = b64decode(self.fixtures["send"]["unsigned_psbt"])
        assert DecodeQR._parse_silent_payments_psbt(raw) is None


    def test_signing_a_send_reproduces_the_transaction_that_confirmed_on_chain(self):
        """The signature and the derived output must match the recorded bytes.

        The DLEQ proof deliberately carries fresh randomness on every signature,
        so the serialised PSBTs differ by exactly those 64 bytes and no others.
        That is asserted rather than tolerated, so a change anywhere ELSE in the
        signed PSBT still fails.
        """
        from base64 import b64decode
        from embit.silent_payments.psbt import SilentPaymentsPSBT

        f = self.fixtures["send"]
        root = self._signing_root(f["sender_mnemonic"])

        parsed = SilentPaymentsPSBT.parse(b64decode(f["unsigned_psbt"]))
        assert parsed.sign_with(root) == 1

        recorded = SilentPaymentsPSBT.parse(b64decode(f["signed_psbt"]))

        # the signature that authorised the spend
        assert parsed.inputs[0].taproot_key_sig == recorded.inputs[0].taproot_key_sig
        # the ECDH shares the receiver scans with (global in BIP-375, not per-input)
        assert parsed.sp_ecdh_shares == recorded.sp_ecdh_shares
        assert parsed.sp_ecdh_shares, "a send with no ECDH share would be unscannable"
        # the DLEQ proof is the one thing that legitimately differs
        assert parsed.sp_dleq_proofs.keys() == recorded.sp_dleq_proofs.keys()
        assert parsed.sp_dleq_proofs != recorded.sp_dleq_proofs
        # and, crucially, where the money went
        for got, want in zip(parsed.outputs, recorded.outputs):
            assert got.script_pubkey == want.script_pubkey

        # Everything except the DLEQ proof must be byte-identical. Copying the
        # recorded proof across and demanding exact equality is the precise
        # statement; counting differing bytes is not, because two random 64-byte
        # proofs share a byte about a fifth of the time.
        parsed.sp_dleq_proofs = dict(recorded.sp_dleq_proofs)
        assert parsed.serialize() == recorded.serialize()


    def test_the_dleq_proof_is_the_only_thing_that_moves_between_runs(self):
        """Pins the claim the test above relies on, rather than assuming it."""
        from base64 import b64decode
        from embit.silent_payments.psbt import SilentPaymentsPSBT

        f = self.fixtures["send"]
        root = self._signing_root(f["sender_mnemonic"])

        signed = []
        for _ in range(2):
            p = SilentPaymentsPSBT.parse(b64decode(f["unsigned_psbt"]))
            p.sign_with(root)
            signed.append(p)

        # The proofs themselves differ every time...
        assert signed[0].sp_dleq_proofs != signed[1].sp_dleq_proofs
        assert signed[0].sp_dleq_proofs.keys() == signed[1].sp_dleq_proofs.keys()
        for proof in signed[0].sp_dleq_proofs.values():
            assert len(proof) == 64

        # ...and nothing else does.
        signed[0].sp_dleq_proofs = dict(signed[1].sp_dleq_proofs)
        assert signed[0].serialize() == signed[1].serialize()


    def test_the_sender_seed_is_the_one_that_signed_on_chain(self):
        f = self.fixtures["send"]
        root = self._signing_root(f["sender_mnemonic"])
        assert root.my_fingerprint.hex() == "73c5da0a"
