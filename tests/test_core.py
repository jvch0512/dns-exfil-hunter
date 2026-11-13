import os, random, unittest
from dns_exfil_hunter import core
from dns_exfil_hunter.cli import main

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "..", "examples", "queries.csv")


def rows(n, mk, qtype="A", client="10.0.0.1", rcode="NOERROR"):
    return [core.Query(1000.0 + i, client, mk(i), qtype, rcode) for i in range(n)]


class T(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(core.registered_domain("a.b.example.com"), "example.com")
        self.assertEqual(core.registered_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(core.registered_domain("EXAMPLE.com."), "example.com")

    def test_entropy(self):
        self.assertEqual(core.entropy("aaaa"), 0)
        self.assertAlmostEqual(core.entropy("abcd"), 2.0)
        self.assertGreater(core.entropy("a1b2c3d4e5f6"), core.entropy("aaaabbbbcccc"))

    def test_tunnel_is_detected(self):
        r = random.Random(1)
        qs = rows(60, lambda i: "".join(r.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(48)) + ".t.bad.net", "TXT")
        f = core.analyze(qs)
        self.assertEqual(len(f), 1)
        self.assertGreaterEqual(f[0].score, 85)

    def test_normal_browsing_is_ignored(self):
        names = ["www.example.org", "mail.example.org", "api.example.org"]
        self.assertEqual(core.analyze(rows(200, lambda i: names[i % 3])), [])

    def test_dga_nxdomain_is_flagged(self):
        r = random.Random(2)
        qs = rows(60, lambda i: "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16)) + ".xyz", "A", rcode="NXDOMAIN")
        f = core.analyze(qs)
        self.assertEqual(len(f), 1)
        self.assertTrue(any("domain generation" in x for x in f[0].reasons))
        self.assertEqual(f[0].domain, "(many random domains)")

    def test_allowlist_and_min_queries(self):
        r = random.Random(3)
        qs = rows(60, lambda i: "".join(r.choice("abcdef0123456789") for _ in range(40)) + ".cdn.example", "TXT")
        self.assertEqual(core.analyze(qs, allow={"cdn.example"}), [])
        self.assertEqual(core.analyze(qs[:10]), [])

    def test_parse_errors(self):
        with self.assertRaises(core.InputError):
            core.parse("a,b\n1,2")
        with self.assertRaises(core.InputError):
            core.parse("ts,client,qname,qtype\nx,1,a.b,A")

    def test_html_escapes(self):
        f = core.Finding("<x>", "a.b", 1, 1, 1, 1, 0, 0, 0, 90, ["<script>"])
        self.assertNotIn("<script>", core.page([f], 1))

    def test_sample_file(self):
        with open(SAMPLE) as fh:
            fs = core.analyze(core.parse(fh.read()))
        doms = {f.domain for f in fs}
        self.assertIn("evil-tunnel.net", doms)
        self.assertNotIn("example.org", doms)
        with open(SAMPLE) as fh:
            self.assertNotIn("cdn-assets.example", {f.domain for f in core.analyze(core.parse(fh.read()), allow={"cdn-assets.example"})})

    def test_cli_exit_codes(self):
        self.assertEqual(main([SAMPLE, "--fail-on-find"]), 1)
        self.assertEqual(main(["nope.csv"]), 2)


if __name__ == "__main__":
    unittest.main()
