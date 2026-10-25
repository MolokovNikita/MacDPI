import unittest
from sync_flowseal import import_settings, options, pattern_name

BATCH = r'''
--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_www_google_com.bin" --new
--filter-tcp=80,443 --hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general-user.txt" --dpi-desync=multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_4pda_to.bin" --new
--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new
--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord="%BIN%ACTIVE_DISCORD_UDP.bin" --dpi-desync-fake-stun="%BIN%ACTIVE_DISCORD_UDP.bin" --dpi-desync-repeats=6
'''


class FlowsealImportTests(unittest.TestCase):
    def test_supported_layout_and_repeated_hostlists(self):
        profile = {}
        files = import_settings(profile, BATCH)
        self.assertEqual(profile["google_overlap"], 681)
        self.assertEqual(profile["voice_repeats"], 6)
        self.assertEqual(files["discord_udp"], "ACTIVE_DISCORD_UDP.bin")
        self.assertIn("list-general.txt", options('--hostlist="list-general.txt" --hostlist="user.txt"')["hostlist"])

    def test_unsupported_mode_or_fooling_does_not_import(self):
        for batch in [BATCH.replace("multisplit", "fakedsplit", 1),
                      BATCH.replace("--dpi-desync=multisplit", "--dpi-desync-fooling=md5sig --dpi-desync=multisplit", 1),
                      BATCH.replace("--dpi-desync-repeats=6", "--dpi-desync-repeats=999", 1)]:
            with self.assertRaises(ValueError):
                import_settings({}, batch)

    def test_pattern_paths_cannot_escape_upstream_bin(self):
        for value in ['"%BIN%../private.bin"', '"%BIN%a.bin$(command)"', 'https://example.com/payload.bin']:
            with self.assertRaises(ValueError):
                pattern_name(value)


if __name__ == "__main__":
    unittest.main()
