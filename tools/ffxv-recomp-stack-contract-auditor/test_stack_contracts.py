from __future__ import annotations

import unittest
from pathlib import Path

import verify_stack_contracts as verifier


HERE = Path(__file__).resolve().parent


class StackContractTests(unittest.TestCase):
    def synthetic_case(self, before: bytes, after: bytes) -> tuple[bytes, bytes, str, str]:
        source = b"prefix\n" + before + b"\nsuffix\n"
        output = source.replace(before, after, 1)
        return source, output, verifier.sha256(source), verifier.sha256(output)

    def test_fix72_transform_and_idempotence(self) -> None:
        source, output, source_hash, output_hash = self.synthetic_case(
            verifier.FIX72_BEFORE, verifier.FIX72_AFTER
        )
        transformed = verifier.checked_transform(
            source,
            before=verifier.FIX72_BEFORE,
            after=verifier.FIX72_AFTER,
            input_sha256=source_hash,
            output_sha256=output_hash,
        )
        self.assertEqual(transformed, output)
        self.assertEqual(
            verifier.checked_transform(
                transformed,
                before=verifier.FIX72_BEFORE,
                after=verifier.FIX72_AFTER,
                input_sha256=source_hash,
                output_sha256=output_hash,
            ),
            output,
        )

    def test_fix44_transform_and_idempotence(self) -> None:
        source, output, source_hash, output_hash = self.synthetic_case(
            verifier.FIX44_BEFORE, verifier.FIX44_AFTER
        )
        transformed = verifier.checked_transform(
            source,
            before=verifier.FIX44_BEFORE,
            after=verifier.FIX44_AFTER,
            input_sha256=source_hash,
            output_sha256=output_hash,
        )
        self.assertEqual(transformed, output)
        self.assertEqual(
            verifier.checked_transform(
                transformed,
                before=verifier.FIX44_BEFORE,
                after=verifier.FIX44_AFTER,
                input_sha256=source_hash,
                output_sha256=output_hash,
            ),
            output,
        )

    def test_stale_source_refuses(self) -> None:
        source, _, source_hash, output_hash = self.synthetic_case(
            verifier.FIX72_BEFORE, verifier.FIX72_AFTER
        )
        stale = source + b"changed"
        with self.assertRaisesRegex(verifier.VerificationError, "source hash drift"):
            verifier.checked_transform(
                stale,
                before=verifier.FIX72_BEFORE,
                after=verifier.FIX72_AFTER,
                input_sha256=source_hash,
                output_sha256=output_hash,
            )

    def test_duplicate_anchor_refuses(self) -> None:
        source, _, source_hash, output_hash = self.synthetic_case(
            verifier.FIX44_BEFORE, verifier.FIX44_AFTER
        )
        duplicate = source + verifier.FIX44_BEFORE
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate"):
            verifier.checked_transform(
                duplicate,
                before=verifier.FIX44_BEFORE,
                after=verifier.FIX44_AFTER,
                input_sha256=source_hash,
                output_sha256=output_hash,
            )

    def test_stack_models(self) -> None:
        verifier.verify_stack_models()

    def test_manifest_patch_hashes(self) -> None:
        manifest = verifier.load_manifest()
        for record in manifest["fixes"].values():
            patch = HERE / record["patch"]
            self.assertEqual(verifier.sha256(patch.read_bytes()), record["patch_sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
