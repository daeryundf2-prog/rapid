import unittest

from rapidtriage.artifacts.url_redaction import (
    REDACTED_VALUE,
    redact_secret_text,
    redact_text_urls,
    redact_url,
    redact_url_fields,
    url_sha256,
)


class UrlRedactionTests(unittest.TestCase):
    def test_sensitive_values_replaced_keys_kept(self) -> None:
        url = "https://cdn.discordapp.com/attachments/1/2/a.png?ex=66a&is=66b&hm=abc123&size=1"
        self.assertEqual(
            redact_url(url),
            f"https://cdn.discordapp.com/attachments/1/2/a.png?ex={REDACTED_VALUE}&is={REDACTED_VALUE}&hm={REDACTED_VALUE}&size=1",
        )
        signed = "https://b.s3.amazonaws.com/o?X-Amz-Credential=AKIA%2F1&X-Amz-Signature=dead&X-Amz-Date=20240101"
        out = redact_url(signed)
        self.assertNotIn("dead", out)
        self.assertNotIn("AKIA", out)
        self.assertIn("X-Amz-Date=20240101", out)
        self.assertNotIn("eyJ0", redact_url("https://t.sharepoint.com/download.aspx?UniqueId=1&TEMPAUTH=eyJ0x"))
        self.assertNotIn("s3cr", redact_url("https://a/cb#access_token=s3cr&state=1"))
        slack = redact_url("https://files.slack.com/files-pri/T1-F1/a.pdf?t=xoxe-123-abc")
        self.assertEqual(slack, f"https://files.slack.com/files-pri/T1-F1/a.pdf?t={REDACTED_VALUE}")
        self.assertEqual(redact_url("https://youtube.com/watch?v=1&t=30s"), "https://youtube.com/watch?v=1&t=30s")

    def test_non_sensitive_and_non_strings_untouched(self) -> None:
        for value in ("https://a/?keyword=1&monkey=2", "https://a/?key=", "plain text", "", None, 5):
            self.assertEqual(redact_url(value), value)

    def test_cache_key_with_embedded_urls(self) -> None:
        key = "1/0/_dk_https://a.com https://a.com https://x/y?sig=zzz&v=1"
        self.assertEqual(redact_url(key), f"1/0/_dk_https://a.com https://a.com https://x/y?sig={REDACTED_VALUE}&v=1")

    def test_fields_keep_raw_sha256(self) -> None:
        raw = "https://a/?token=abc"
        row = redact_url_fields({"url": raw, "location": "https://a/b", "n": 1}, ("url", "location", "missing"))
        self.assertEqual(row["url"], f"https://a/?token={REDACTED_VALUE}")
        self.assertEqual(row["url_sha256"], url_sha256(raw))
        self.assertTrue(row["url_tokens_redacted"])
        self.assertNotIn("location_sha256", row)
        values, changed = redact_text_urls(["GET https://a/?sid=1 200", "no url"])
        self.assertTrue(changed)
        self.assertEqual(values[1], "no url")
        self.assertNotIn("sid=1", values[0])

    def test_secret_text_for_timeline_summaries(self) -> None:
        """UX-round review (c): free text hides credential pairs in and outside URLs."""
        hidden = REDACTED_VALUE
        cases = {
            "https://a.blob.core.windows.net/c?sv=1&sharedAccessToken=sas&x=1": f"https://a.blob.core.windows.net/c?sv=1&sharedAccessToken={hidden}&x=1",
            "https://login/cb?code=1&state=xyz": f"https://login/cb?code={hidden}&state={hidden}",
            "net use /user:a password=hunter2": f"net use /user:a password={hidden}",
            'app.exe --api_key="abc def" next': f"app.exe --api_key={hidden} next",
            "x /Password=s3 y": f"x /Password={hidden} y",
            "msg url=https://a/b?token=zz&a=1": f"msg url=https://a/b?token={hidden}&a=1",
            "https://u:p@host/a": f"https://{hidden}@host/a",
            # Prose pairs that are not credentials stay readable.
            "service state=running key=HKLM\\X code=0x5": "service state=running key=HKLM\\X code=0x5",
        }
        for raw, expected in cases.items():
            self.assertEqual(redact_secret_text(raw), expected, raw)
        self.assertEqual(redact_secret_text(f"password={hidden}"), f"password={hidden}")
        self.assertIsNone(redact_secret_text(None))
        # The URL helper the parsers use is unchanged: state stays a plain query value there.
        self.assertEqual(redact_url("https://login/cb?state=xyz"), "https://login/cb?state=xyz")


if __name__ == "__main__":
    unittest.main()
