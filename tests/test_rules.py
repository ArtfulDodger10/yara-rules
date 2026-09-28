"""
Run with:  python -m unittest discover -s tests -v

Checks that every rule compiles and has complete metadata, then checks each rule's
logic against small C# programs built at test time. The programs only contain the
names and strings a rule looks for; they do nothing when run. Each positive case
has a near-miss that must not match, so a loosened or broken condition shows up here.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yara

ROOT = Path(__file__).resolve().parent.parent
RULE_FILES = sorted((ROOT / "rules").rglob("*.yar"))
REQUIRED_META = ("description", "author", "date", "family")

CSC = next((p for p in (
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
    shutil.which("csc"),
    shutil.which("mcs"),
) if p and os.path.exists(p)), None)


def compile_all() -> yara.Rules:
    return yara.compile(filepaths={f.parent.name + "/" + f.stem: str(f) for f in RULE_FILES})


def hits(rules: yara.Rules, **kwargs) -> set:
    return {m.rule for m in rules.match(**kwargs)}


class TestRuleFiles(unittest.TestCase):
    def test_every_file_compiles(self):
        self.assertTrue(RULE_FILES)
        for f in RULE_FILES:
            with self.subTest(file=f.name):
                yara.compile(filepath=str(f))

    def test_metadata(self):
        for rule in compile_all():
            for key in REQUIRED_META:
                with self.subTest(rule=rule.identifier, meta=key):
                    self.assertTrue(rule.meta.get(key))

    def test_unique_rule_names(self):
        names = [r.identifier for r in compile_all()]
        self.assertEqual(len(names), len(set(names)))


class TestMemoryRules(unittest.TestCase):
    rules = compile_all()

    def test_agenttesla_smtp(self):
        self.assertIn("AgentTesla_Campaign_SMTP_Memory",
                      hits(self.rules, data=b"..mail.albushrametalic.com..saeed9797seead@gmail.com.."))
        self.assertNotIn("AgentTesla_Campaign_SMTP_Memory",
                         hits(self.rules, data=b"..mail.albushrametalic.com.."))

    def test_asyncrat_config(self):
        wide = "hubscore.io rxUf9crL1mff".encode("utf-16-le")
        self.assertIn("AsyncRAT_Campaign_xTeam_Memory", hits(self.rules, data=wide))
        self.assertNotIn("AsyncRAT_Campaign_xTeam_Memory", hits(self.rules, data=b"hubscore.io"))


@unittest.skipUnless(CSC, "no C# compiler available")
class TestRuleLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = compile_all()
        cls.tmp = tempfile.mkdtemp(prefix="yara_rules_test_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def build(self, name: str, body: str, usings: str = "") -> str:
        src = Path(self.tmp) / f"{name}.cs"
        exe = Path(self.tmp) / f"{name}.exe"
        src.write_text(f"using System;\n{usings}\npublic static class P {{\n{body}\n"
                       "    public static void Main() { }\n}\n", encoding="utf-8")
        subprocess.run([CSC, "/nologo", "/target:exe", f"/out:{exe}", str(src)], check=True, capture_output=True)
        return str(exe)

    @staticmethod
    def strings_field(values) -> str:
        items = ", ".join('"' + v.replace("\\", "\\\\") + '"' for v in values)
        return f"    static string[] s = {{ {items} }};"

    def test_xworm_generic(self):
        commands = ["StartDDos", "StopDDos", "PCShutdown", "PCRestart", "PCLogoff", "RunShell", "OfflineGet"]
        positive = self.build("xworm_pos", self.strings_field(commands))
        negative = self.build("xworm_neg", self.strings_field(commands[:6]))
        self.assertIn("XWorm_Payload_Generic", hits(self.rules, filepath=positive))
        self.assertNotIn("XWorm_Payload_Generic", hits(self.rules, filepath=negative))

    def test_agenttesla_loader(self):
        positive = self.build("at_pos", self.strings_field(["PY718E785ZXFG4844GPE4Z"]))
        negative = self.build("at_neg", self.strings_field(["PY718E785ZXFG4844GPE4"]))
        self.assertIn("AgentTesla_Loader_FF_Resource", hits(self.rules, filepath=positive))
        self.assertNotIn("AgentTesla_Loader_FF_Resource", hits(self.rules, filepath=negative))

    def test_asyncrat_generic(self):
        usings = ("using System.Net.Security;\nusing System.Net.Sockets;\n"
                  "using System.Security.Cryptography;\nusing System.Runtime.InteropServices;")
        common = """
    static void Refs(SslStream ssl) {
        ssl.AuthenticateAsClient("x");
        var t = new TcpClient();
        var a = new AesCryptoServiceProvider();
        var d = new Rfc2898DeriveBytes("p", new byte[8], 1);
        var h = new HMACSHA256();
    }
"""
        pinvoke = """
    [DllImport("ntdll.dll")] static extern int RtlSetProcessIsCritical(bool a, IntPtr b, bool c);
"""
        strings = self.strings_field(["SbieDll.dll", "VirtualBox", "Select * from AntivirusProduct"])
        positive = self.build("ar_pos", common + pinvoke + strings, usings)
        no_pinvoke = self.build("ar_neg1", common + strings, usings)
        one_string = self.build("ar_neg2", common + pinvoke + self.strings_field(["VirtualBox"]), usings)
        self.assertIn("AsyncRAT_Payload_Generic", hits(self.rules, filepath=positive))
        self.assertNotIn("AsyncRAT_Payload_Generic", hits(self.rules, filepath=no_pinvoke))
        self.assertNotIn("AsyncRAT_Payload_Generic", hits(self.rules, filepath=one_string))

    def test_clean_program(self):
        clean = self.build("clean", self.strings_field(["hello", "world"]))
        self.assertEqual(hits(self.rules, filepath=clean), set())


if __name__ == "__main__":
    unittest.main()
