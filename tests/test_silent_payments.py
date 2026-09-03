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
