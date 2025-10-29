"""DeobfuScripter: Script Deobfuscation Service."""

from __future__ import annotations

import binascii
import os
import regex
from collections import Counter, defaultdict
from functools import partial
from itertools import chain
from typing import Callable, Optional

from assemblyline.common.str_utils import safe_str
from assemblyline_service_utilities.common.extractor.decode_wrapper import DecoderWrapper, get_tree_tags
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import MaxExtractedExceeded, ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, Result, ResultSection
from bs4 import BeautifulSoup
from multidecoder._version import version as multidecoder_version

# Type declarations
TechniqueList = list[tuple[str, Callable[[bytes], Optional[bytes]]]]


def filter_iocs(
    iocs: dict[str, set[bytes]],
    original: bytes,
    seen: set[bytes],
    *,
    reversed: object = False,
) -> dict[str, set[bytes]]:
    """Filter IOCs against the original text and those already found."""
    new_iocs: defaultdict[str, set[bytes]] = defaultdict(set)
    original = original.lower()
    for ioc_type in iocs:
        for ioc in sorted(iocs[ioc_type]):
            prefix = b"/".join(ioc.split(b"/", 3)[:3]) if ioc_type == "network.static.uri" else ioc
            if reversed:
                prefix = prefix[::-1]
            prefix = prefix.lower()
            if prefix not in seen and prefix not in original:
                seen.add(prefix)
                new_iocs[ioc_type].add(ioc)
    return new_iocs


class DeobfuScripter(ServiceBase):
    """Service for deobfuscating scripts."""

    VALIDCHARS = b" 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    BINCHARS = bytes(list(set(range(256)) - set(VALIDCHARS)))

    # === PRE-COMPILED REGEX PATTERNS (Easy Win) ===
    _RE_POWERSHELL_CARET = regex.compile(rb'"[^"]+[A-Za-z0-9](\^|`)+[A-Za-z0-9][^"]+"')
    _RE_VAR_ASSIGN_ARRAY = regex.compile(rb"var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\s*;")
    _RE_FAKE_ARRAY_REF = regex.compile(rb"([^\s=]+)\s*=\s*\[([^\]]+)\]\[(\d+)\]")
    _RE_XOR_FUNC = regex.compile(rb'(\w+\("((?:[0-9A-Fa-f][0-9A-Fa-f])+)"\s*,\s*"([^"]+)"\))')
    _RE_POWERSHELL_VAR_STR = regex.compile(rb"(\$(?:\w+|{[^\}]+\}))\s*=[^=]\s*[\"\']([^\"\']+)[\"\']")
    _RE_POWERSHELL_VAR_FUNC = regex.compile(rb"(\$(?:\w+|{[^\}]+\}))\s*=\s*([^=\"\'\s$]{3,50})[\s]")
    _RE_MSOFFICE_VAR = regex.compile(
        rb'^(\s*(\w+)\s*=\s*\w*\s*\+?\s(["\'])(.+)["\']\s*\+\s*vbCrLf\s*$)', regex.M
    )
    _RE_MSWORD_VAR = regex.compile(
        rb"^\s*((?:Const[\s]*)?(\w+)\s*=\s*((?:[\"][^\"]+[\"]|[\'][^\']+[\']|[0-9]*)))[\s\r]*$",
        regex.MULTILINE | regex.DOTALL,
    )
    _RE_MSWORD_STACKED = regex.compile(
        rb"^\s*((\w+)\s*=\s*(\w+)\s*[+&]\s*((?:[\"][^\"]+[\"]|[\'][^\']+[\'])))[\s\r]*$",
        regex.MULTILINE | regex.DOTALL,
    )
    _RE_HEX_CHAR = regex.compile(rb"(?i)(?:\\x|%)([a-f0-9]{2})")
    _RE_UNICODE_CHAR = regex.compile(rb"(?i)(?:\\u|%u)([a-f0-9]{4})")
    _RE_XML_CHAR_HEX = regex.compile(rb"(?i)&#x([a-z0-9]{1,6});")
    _RE_XML_CHAR_DEC = regex.compile(rb"&#([0-9]{1,7});")
    _RE_HEX_CONST = regex.compile(rb"(?i)\b0x([a-f0-9]{1,16})\b")

    # === FILE-TYPE TECHNIQUE SKIP LIST (Easy Win) ===
    SKIP_BY_TYPE = {
        "html": {"MSWord macro vars", "MSOffice Embedded script"},
        "ps1": {"Array of strings", "Fake array vars"},
        "vba": {"Powershell vars", "Powershell carets"},
    }

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)

    def get_tool_version(self) -> str:
        return f"Multidecoder: {multidecoder_version}"

    # --- Support Modules ----------------------------------------------------------------------------------------------

    def printable_ratio(self, text: bytes) -> float:
        return len(text.translate(None, self.BINCHARS)) / len(text) if text else 0.0

    @staticmethod
    def encode_codepoint(codepoint: int) -> bytes:
        return chr(codepoint).encode("utf-8")

    @staticmethod
    def codepoint_sub(match: regex.Match[bytes], base: int = 16) -> bytes:
        try:
            return DeobfuScripter.encode_codepoint(int(match.group(1), base))
        except ValueError:
            return match.group(0)

    @staticmethod
    def xor_with_key(s: bytes, k: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(s, (len(s) // len(k) + 1) * k))

    @staticmethod
    def clean_up_final_layer(text: bytes) -> bytes:
        text = regex.sub(rb"\r", b"", text)
        return regex.sub(rb"<deobsfuscripter:[^>]+>\n?", b"", text)

    # --- Optimized Techniques (Batched + Compiled) ---

    def charcode_hex(self, text: bytes) -> bytes | None:
        if b"\\x" not in text and b"%" not in text:
            return None
        return self._RE_HEX_CHAR.sub(lambda m: binascii.unhexlify(m.group(1)), text)

    def charcode_unicode(self, text: bytes) -> bytes | None:
        if b"\\u" not in text and b"%u" not in text:
            return None
        return self._RE_UNICODE_CHAR.sub(self.codepoint_sub, text)

    def charcode_xml(self, text: bytes) -> bytes | None:
        if b"&#" not in text:
            return None
        text = self._RE_XML_CHAR_HEX.sub(self.codepoint_sub, text)
        text = self._RE_XML_CHAR_DEC.sub(partial(self.codepoint_sub, base=10), text)
        return text

    def hex_constant(self, text: bytes) -> bytes | None:
        if b"0x" not in text.lower():
            return None
        return self._RE_HEX_CONST.sub(lambda m: str(int(m.group(1), 16)).encode(), text)

    def powershell_vars(self, text: bytes) -> bytes | None:
        if b"$" not in text:
            return None
        reps_str = self._RE_POWERSHELL_VAR_STR.findall(text)
        reps_func = self._RE_POWERSHELL_VAR_FUNC.findall(text)
        all_reps = list(chain(reps_str, reps_func))
        if not all_reps:
            return None

        patterns = []
        seen = set()
        for var, val in all_reps:
            if var not in seen:
                patterns.append((regex.escape(var), val))
                seen.add(var)

        if not patterns:
            return None

        alt = b"|".join(p[0] for p in patterns)
        def repl(m):
            idx = next(i for i, (pat, _) in enumerate(patterns) if m.group(0) == pat)
            return patterns[idx][1]
        return regex.sub(b"(" + alt + b")", repl, text, count=100)

    def powershell_carets(self, text: bytes) -> bytes | None:
        if b"^" not in text and b"`" not in text:
            return None
        matches = self._RE_POWERSHELL_CARET.findall(text)
        if not matches:
            return None
        output = text
        for full in matches:
            if isinstance(full, tuple):
                full = full[0]
            remove_char = b"^" if b"^" in full else b"`"
            output = output.replace(full, full.replace(remove_char, b""))
        return output if output != text else None

    def array_of_strings(self, text: bytes) -> bytes | None:
        if b"[" not in text or b"]" not in text:
            return None
        matches = self._RE_VAR_ASSIGN_ARRAY.findall(text)
        if not matches:
            return None
        output = text
        for varname, values in matches:
            indices = [int(x) for x in regex.findall(varname + rb"\s*\[(\d+)\]", output)]
            parts = [p.strip() for p in values.split(b",")]
            for i in indices:
                if i >= len(parts):
                    continue
                repl = parts[i].replace(b"\\", b"\\\\")
                output = regex.sub(varname + rb"\s*\[%d\]" % i, repl, output, count=1)
        return output if output != text else None

    def vars_of_fake_arrays(self, text: bytes) -> bytes | None:
        if b"[" not in text:
            return None
        matches = self._RE_FAKE_ARRAY_REF.findall(text)
        if not matches:
            return None
        output = regex.sub(rb"var\s+[^=]+=", b"XXX ", text)
        for varname, array, pos in matches:
            try:
                value = regex.split(rb"\s*,\s*", array)[int(pos)]
                output = output.replace(varname, value)
            except IndexError:
                continue
        return output if output != text else None

    def simple_xor_function(self, text: bytes) -> bytes | None:
        if b"(" not in text or b'"' not in text:
            return None
        matches = self._RE_XOR_FUNC.findall(text)
        if not matches:
            return None
        output = text
        for f, x, k in matches:
            data = binascii.a2b_hex(x)
            for key in (k, k[1:] + k[:1]):
                res = self.xor_with_key(data, key)
                if self.printable_ratio(res) == 1.0:
                    output = output.replace(f, b'"' + res + b'"')
                    break
        return output if output != text else None

    def msoffice_embedded_script_string(self, text: bytes) -> bytes | None:
        if b"vbCrLf" not in text:
            return None
        matches = self._RE_MSOFFICE_VAR.findall(text)
        if not matches:
            return None
        scripts = {}
        output = text
        for full, var, delim, val in matches:
            scripts.setdefault(var, []).append(val.replace(delim + delim, delim))
            output = output.replace(full, b"<deobsfuscripter:msoffice_var>")
        for var, lines in scripts.items():
            new_name = b"new_script__" + var
            output = regex.sub(rb"\b" + var + rb"\b", new_name, output)
            output += b"\n\n' ---- script ----\n" + b"\n".join(lines) + b"\n"
        return output

    def mswordmacro_vars(self, text: bytes) -> bytes | None:
        if b"=" not in text:
            return None
        output = text
        reps = self._RE_MSWORD_VAR.findall(output)
        if not reps:
            return None
        var_map = {k: v[1].strip(b'"\'').replace(b'""', b'"') for _, k, v in reps}
        for full, var, _ in reps:
            output = output.replace(full, b"<deobsfuscripter:msword_var>")
        stacked = self._RE_MSWORD_STACKED.findall(output)
        for _, target, _, val in stacked:
            if target in var_map:
                var_map[target] += val.strip(b'"\'')
        for var, val in var_map.items():
            pattern = regex.compile(rb"\b" + regex.escape(var) + rb"\b(?![\s=])")
            output = pattern.sub(b'"' + val.replace(b"\\", b"\\\\") + b'"', output, count=5)
        return output if output != text else None

    def extract_htmlscript(self, text: bytes) -> list[bytes]:
        if (b"<html" not in text.lower()[:500] and
            b"<script" not in text.lower()[:500] and
            b"<object" not in text.lower()[:500]):
            return []
        try:
            soup = BeautifulSoup(text, "lxml")
            return [str(tag).encode("utf-8") for tag in soup.find_all(["script", "object", "embed"])]
        except Exception as e:
            self.log.warning(f"HTML extraction failed: {e!s}")
            return []

    # --- Execute --------------------------------------------------------------------------------------------------

    def execute(self, request: ServiceRequest) -> None:
        request.result = Result()
        if request.task.file_size > request.get_param("max_file_size"):
            return

        md = DecoderWrapper(self.working_directory)
        max_attempts = 100 if request.deep_scan else 10
        file_type = request.task.file_type or ""

        # === Filter techniques by file type (Easy) ===
        skip_techs = self.SKIP_BY_TYPE.get(file_type.split("/")[-1], set())
        first_pass: TechniqueList = [
            ("MSOffice Embedded script", self.msoffice_embedded_script_string),
            ("Powershell carets", self.powershell_carets),
            ("Array of strings", self.array_of_strings),
            ("Fake array vars", self.vars_of_fake_arrays),
            ("Simple XOR function", self.simple_xor_function),
        ]
        second_pass: TechniqueList = [
            ("MSWord macro vars", self.mswordmacro_vars),
            ("Powershell vars", self.powershell_vars),
            ("Hex Charcodes", self.charcode_hex),
            ("Unicode Charcodes", self.charcode_unicode),
            ("XML Charcodes", self.charcode_xml),
            ("Hex Int Constants", self.hex_constant),
        ] + first_pass

        first_pass = [t for t in first_pass if t[0] not in skip_techs]
        second_pass = [t for t in second_pass if t[0] not in skip_techs]

        code_extracts = [(".*html.*", "HTML scripts extraction", self.extract_htmlscript)]
        layer = request.file_contents

        # --- Stage 1: Script Extraction ---
        extract_res = ResultSection("Extraction")
        for pattern, name, func in code_extracts:
            if regex.match(pattern, file_type, regex.I):
                parts = func(request.file_contents)
                layer = b"\n".join(parts).strip()
                extract_res.add_line(name)
                break

        if len(layer.strip()) < 3:
            return

        if file_type == "code/ps1":
            sig = regex.search(
                rb"# SIG # Begin signature block\r\n(?:# [A-Za-z0-9+/=]+\r\n)+# SIG # End signature block",
                request.file_contents,
            )
            if sig:
                layer = layer[:sig.start()] + layer[sig.end():]
                lines = sig.group().split(b"\r\n# ")
                base64 = b"".join(line.strip() for line in lines[1:-1])
                try:
                    signature = binascii.a2b_base64(base64)
                    sig_filename = "powershell_signature"
                    sig_path = os.path.join(self.working_directory, sig_filename)
                    with open(sig_path, "wb+") as f:
                        f.write(signature)
                    request.add_extracted(sig_path, sig_filename, "Powershell Signature")
                    extract_res.add_line(f"Powershell Signature Comment, see {sig_filename}")
                except binascii.Error:
                    pass

        if extract_res.body:
            request.result.add_section(extract_res)
        before_deobfuscation = layer

        # --- Stage 2: Deobfuscation with Stagnation Exit (Critical) ---
        seen_iocs: set[bytes] = set()
        tech_count: Counter[str] = Counter()
        pass_iocs: list[dict[str, set[bytes]]] = []
        techniques = first_pass
        stagnant_passes = 0
        max_stagnant = 3

        for n_pass in range(max_attempts):
            prev_layer = layer
            layer, tech_used, iocs = self._deobfuscripter_pass(layer, techniques, md)

            pass_iocs.append(filter_iocs(iocs, before_deobfuscation, seen_iocs))
            if tech_used:
                tech_count.update(tech_used)
                stagnant_passes = 0
            else:
                stagnant_passes += 1

            if layer == prev_layer:
                if stagnant_passes >= max_stagnant:
                    break
                if techniques is first_pass:
                    techniques = second_pass
            else:
                stagnant_passes = 0

        rev_iocs = filter_iocs(md.ioc_tags(layer[::-1]), before_deobfuscation, seen_iocs, reversed=True)

        # --- Results ---
        if not tech_count:
            return

        clean = self.clean_up_final_layer(layer)
        if clean == request.file_contents:
            return

        heuristic = Heuristic(1)
        mres = ResultSection("De-obfuscation steps taken by DeobsfuScripter", heuristic=heuristic, parent=request.result)
        for tech, count in sorted(tech_count.items()):
            heuristic.add_signature_id(tech, frequency=count)
            mres.add_line(f"{tech}, {count} time(s).")

        byte_count = 5000
        if request.deep_scan or len(clean) > 1000:
            byte_count = 500
            path = os.path.join(self.working_directory, f"{request.sha256}_decoded_final")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(clean)
            request.add_supplementary(path, os.path.basename(path), "Final deobfuscated layer")

        ResultSection(
            f"First {byte_count} bytes of the final layer:",
            body=safe_str(clean[:byte_count]),
            body_format=BODY_FORMAT.MEMORY_DUMP,
            parent=request.result,
        )

        new_ioc_res = ResultSection("New IOCs found after de-obfuscation", heuristic=Heuristic(6), body_format=BODY_FORMAT.MEMORY_DUMP)
        for n_pass, iocs in enumerate(pass_iocs):
            if not iocs:
                continue
            new_ioc_res.add_line(f"Pass {n_pass}:")
            for t, vals in iocs.items():
                for v in sorted(vals):
                    new_ioc_res.add_line(f"  {t.upper()}: {safe_str(v)}")
                    new_ioc_res.add_tag(t, v)
        if rev_iocs:
            new_ioc_res.add_line("Reversed IOCs:")
            for t, vals in rev_iocs.items():
                for v in sorted(vals):
                    new_ioc_res.add_line(f"  {t.upper()}: {safe_str(v)}")
                    new_ioc_res.add_tag(t, v)
        if new_ioc_res.body:
            request.result.add_section(new_ioc_res)

        if md.extracted_files:
            ext_res = ResultSection("Extracted files", heuristic=Heuristic(8), parent=request.result)
            for path in md.extracted_files:
                name = os.path.basename(path)
                try:
                    if request.add_extracted(path, name, "Deobfuscated file"):
                        ext_res.add_line(name)
                except MaxExtractedExceeded:
                    break
            request.result.add_section(ext_res)

    @staticmethod
    def _deobfuscripter_pass(
        layer: bytes,
        techniques: TechniqueList,
        md: DecoderWrapper,
    ) -> tuple[bytes, set[str], dict[str, set[bytes]]]:
        tree = md.multidecoder.scan(layer, depth=1)
        md.extract_files(tree, 100 if len(layer) < 5000 else 500)
        techniques_used = {node.obfuscation for node in tree if node.obfuscation}
        iocs = get_tree_tags(tree)
        layer = tree.flatten()

        for name, tech in techniques:
            result = tech(layer)
            if result and result != layer:
                techniques_used.add(name)
                layer = result

        return layer, techniques_used, iocs
