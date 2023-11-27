"""DeobfuScripter: Script Deobfuscation Service."""

from __future__ import annotations

import binascii
import os
from collections import Counter, defaultdict
from functools import partial
from typing import Callable, Optional

import regex
from assemblyline.common.str_utils import safe_str
from assemblyline_service_utilities.common.extractor.decode_wrapper import DecoderWrapper, get_tree_tags
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import MaxExtractedExceeded, ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, Result, ResultSection
from bs4 import BeautifulSoup

# Type declarations
TechniqueList = list[tuple[str, Callable[[bytes], Optional[bytes]]]]


def filter_iocs(
    iocs: dict[str, set[bytes]],
    original: bytes,
    seen: set[bytes],
    *,
    reversed: object = False,
) -> dict[str, set[bytes]]:
    """Filter IOCs against the original text and those already found.

    IOCs are filtered if they are found in original or are in seen.
    network.static.uri tags are filtered based on segments before the path only.
    """
    new_iocs: defaultdict[str, set[bytes]] = defaultdict(set)
    for ioc_type in iocs:
        for ioc in iocs[ioc_type]:
            prefix = b"/".join(ioc.split(b"/", 3)[:3]) if ioc_type == "network.static.uri" else ioc
            if reversed:
                prefix = prefix[::-1]
            if prefix not in seen and prefix not in original:
                seen.add(prefix)
                new_iocs[ioc_type].add(ioc)
    return new_iocs


class DeobfuScripter(ServiceBase):
    """Service for deobfuscating scripts."""

    VALIDCHARS = b" 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    BINCHARS = bytes(list(set(range(256)) - set(VALIDCHARS)))

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)

    # --- Support Modules ----------------------------------------------------------------------------------------------

    def printable_ratio(self, text: bytes) -> float:
        """Calcuate the ratio of printable characters to total characters in text."""
        return float(float(len(text.translate(None, self.BINCHARS))) / float(len(text)))

    @staticmethod
    def encode_codepoint(codepoint: int) -> bytes:
        """Get the encoding from unicode codepoint."""
        return chr(codepoint).encode("utf-8")

    @staticmethod
    def codepoint_sub(match: regex.Match[bytes], base: int = 16) -> bytes:
        """Replace method for unicode codepoint regex substitutions.

        Args:
            match: The regex match object with the text of the unicode codepoint value as group 1.
            base: The base that the unicode codepoint is represented in (defaults to hexadecimal)

        Returns:
            - The utf-8 byte sequence for the codepoint if it can be decoded.
            - The original match text if there is a decoding error.
        """
        try:
            return DeobfuScripter.encode_codepoint(int(match.group(1), base))
        except ValueError:
            return match.group(0)  # No replacement if decoding fails

    @staticmethod
    def add1b(s: bytes, k: int) -> bytes:
        """Add k to each byte of s."""
        return bytes([(c + k) & 0xFF for c in s])

    @staticmethod
    def charcode(text: bytes) -> bytes | None:
        """Replace character codes with the corresponding characters."""
        # TODO: something to handle powershell bytes syntax

    @staticmethod
    def charcode_hex(text: bytes) -> bytes | None:
        """Replace hex character codes with the corresponding characters."""
        output = regex.sub(rb"(?i)(?:\\x|%)([a-f0-9]{2})", lambda m: binascii.unhexlify(m.group(1)), text)
        return output if output != text else None

    # TODO: find a way to prevent charcode_oct from mangling windows filepaths with sections that start with 0-7
    @staticmethod
    def charcode_oct(text: bytes) -> bytes | None:
        """Replace octal character codes with the corresponding characters."""
        output = regex.sub(rb"\\([0-7]{1,3})", partial(DeobfuScripter.codepoint_sub, base=8), text)
        return output if output != text else None

    @staticmethod
    def charcode_unicode(text: bytes) -> bytes | None:
        """Replace unicode character codes with the corresponding utf-8 byte sequence."""
        output = regex.sub(rb"(?i)(?:\\u|%u)([a-f0-9]{4})", DeobfuScripter.codepoint_sub, text)
        return output if output != text else None

    @staticmethod
    def charcode_xml(text: bytes) -> bytes | None:
        """Replace XML escape sequences with the corresponding character."""
        output = regex.sub(rb"(?i)&#x([a-z0-9]{1,6});", DeobfuScripter.codepoint_sub, text)
        output = regex.sub(rb"&#([0-9]{1,7});", partial(DeobfuScripter.codepoint_sub, base=10), output)
        return output if output != text else None

    @staticmethod
    def hex_constant(text: bytes) -> bytes | None:
        """Replace hexadecimal integer constants with decimal ones."""
        output = regex.sub(rb"(?i)\b0x([a-f0-9]{1,16})\b", lambda m: str(int(m.group(1), 16)).encode("utf-8"), text)
        return output if output != text else None

    @staticmethod
    def vars_of_fake_arrays(text: bytes) -> bytes | None:
        """Parse variables of fake arrays."""
        replacements = regex.findall(rb"var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\[(\d+)\]", text)
        if len(replacements) > 0:
            #    ,- Make sure we do not process these again
            output = regex.sub(rb"var\s+([^=]+)\s*=", rb"XXX \1 =", text)
            for varname, array, pos in replacements:
                try:
                    value = regex.split(rb"\s*,\s*", array)[int(pos)]
                except IndexError:
                    break
                output = output.replace(varname, value)
            if output != text:
                return output
        return None

    def array_of_strings(self, text: bytes) -> bytes | None:
        """Replace arrays of strings with the combined string."""
        # noinspection PyBroadException
        try:
            replacements = regex.findall(rb"var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\s*;", text)
            if len(replacements) > 0:
                #    ,- Make sure we do not process these again
                output = text
                for varname, values in replacements:
                    occurences = [int(x) for x in regex.findall(varname + rb"\s*\[(\d+)\]", output)]
                    for i in occurences:
                        try:
                            output = regex.sub(
                                varname + rb"\s*\[(%d)\]" % i,
                                values.split(b",")[i].replace(b"\\", b"\\\\"),
                                output,
                            )
                        except IndexError:
                            break
                if output != text:
                    return output
        except Exception as e:
            self.log.warning(f"Technique array_of_strings failed with error: {e!s}")

        return None

    @staticmethod
    def powershell_vars(text: bytes) -> bytes | None:
        """Replace PowerShell variables with their values."""
        replacements_string = regex.findall(rb"(\$(?:\w+|{[^\}]+\}))\s*=[^=]\s*[\"\']([^\"\']+)[\"\']", text)
        replacements_func = regex.findall(rb"(\$(?:\w+|{[^\}]+\}))\s*=\s*([^=\"\'\s$]{3,50})[\s]", text)
        if len(replacements_string) > 0 or len(replacements_func) > 0:
            #    ,- Make sure we do not process these again
            output = regex.sub(rb"\$((?:\w+|{[^\}]+\}))\s*=", rb"\$--\1 =", text)
            for varname, string in replacements_string:
                output = output.replace(varname, string)
            for varname, string in replacements_func:
                output = output.replace(varname, string)
            if output != text:
                return output

        return None

    @staticmethod
    def powershell_carets(text: bytes) -> bytes | None:
        """Remove PowerShell carets."""
        try:
            if b"^" in text or b"`" in text:
                output = text
                for full in regex.findall(rb'"[^"]+[A-Za-z0-9](\^|`)+[A-Za-z0-9][^"]+"', text):
                    if isinstance(full, tuple):
                        full = full[0]
                    char_to_be_removed = b"^" if b"^" in full else b"`"
                    output = output.replace(full, full.replace(char_to_be_removed, b""))
                if output == text:
                    return None
                return output
        except TimeoutError:
            pass
        return None

    # noinspection PyBroadException
    def msoffice_embedded_script_string(self, text: bytes) -> bytes | None:
        """Replace variables with their values in MSOffice embedded scripts."""
        try:
            scripts: dict[bytes, list[bytes]] = {}
            output = text
            # bad, prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = regex.findall(
                rb'^(\s*(\w+)\s*=\s*\w*\s*\+?\s(["\'])(.+)["\']\s*\+\s*vbCrLf\s*$)',
                output,
                regex.M,
            )
            if len(replacements) > 0:
                for full, variable_name, delim, value in replacements:
                    scripts.setdefault(variable_name, [])
                    scripts[variable_name].append(value.replace(delim + delim, delim))
                    output = output.replace(full, b"<deobsfuscripter:msoffice_embedded_script_string_var_assignment>")

            for script_var, script_lines in scripts.items():
                new_script_name = b"new_script__" + script_var
                output = regex.sub(rb"(.+)\b" + script_var + rb"\b", b"\\1" + new_script_name, output)
                output += b"\n\n\n' ---- script referenced by \"" + new_script_name + b'" ----\n\n\n'
                output += b"\n".join(script_lines)

            if output == text:
                return None
            return output

        except Exception as e:
            self.log.warning(f"Technique msoffice_embedded_script_string failed with error: {e!s}")
            return None

    def mswordmacro_vars(self, text: bytes) -> bytes | None:
        """Replace Microsoft Word variables with their values."""
        # noinspection PyBroadException
        try:
            output = text
            # prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = regex.findall(
                rb"^\s*((?:Const[\s]*)?(\w+)\s*=" rb'\s*((?:["][^"]+["]|[\'][^\']+[\']|[0-9]*)))[\s\r]*$',
                output,
                regex.MULTILINE | regex.DOTALL,
            )
            if len(replacements) > 0:
                # If one variable is defined more then once take the second definition
                replacements = [(v[0], k, v[1]) for k, v in {i[1]: (i[0], i[2]) for i in replacements}.items()]
                for full, varname, value in replacements:
                    if len(regex.findall(rb"\b" + varname + rb"\b", output)) == 1:
                        # If there is only one instance of these, it's probably noise.
                        output = output.replace(full, b"<deobsfuscripter:mswordmacro_unused_variable_assignment>")
                    else:
                        final_val = value.replace(b'"', b"")
                        # Stacked strings
                        # b = "he"
                        # b = b & "llo "
                        # b = b & "world!"
                        stacked = regex.findall(
                            rb"^\s*("
                            + varname
                            + rb"\s*=\s*"
                            + varname
                            + rb'\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\'])))[\s\r]*$',
                            output,
                            regex.MULTILINE | regex.DOTALL,
                        )
                        if len(stacked) > 0:
                            for sfull, val in stacked:
                                final_val += val.replace(b'"', b"")
                                output = output.replace(sfull, b"<deobsfuscripter:mswordmacro_var_assignment>")
                        output = output.replace(full, b"<deobsfuscripter:mswordmacro_var_assignment>")
                        # If more than a of the variable name left, the assumption is that this did not
                        # work according to plan, so just replace a few for now.
                        output = regex.sub(
                            rb"(\b"
                            + regex.escape(varname)
                            + rb"(?!\s*(?:=|[+&]\s*"
                            + regex.escape(varname)
                            + rb"))\b)",
                            b'"' + final_val.replace(b"\\", b"\\\\") + b'"',
                            output,
                            count=5,
                        )

            # Remaining stacked strings
            replacements = regex.findall(
                rb'^\s*((\w+)\s*=\s*(\w+)\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\'])))[\s\r]*$',
                output,
                regex.MULTILINE | regex.DOTALL,
            )
            replacements_vars = {x[1] for x in replacements}
            for v in replacements_vars:
                final_val = b""
                for full, varname, _, value in replacements:
                    if varname != v:
                        continue
                    final_val += value.replace(b'"', b"")
                    output = output.replace(full, b"<deobsfuscripter:mswordmacro_var_assignment>")
                output = regex.sub(
                    rb"(\b" + v + rb"(?!\s*(?:=|[+&]\s*" + v + rb"))\b)",
                    b'"' + final_val.replace(b"\\", b"\\\\") + b'"',
                    output,
                    count=5,
                )

            if output == text:
                return None
            return output

        except Exception as e:
            self.log.warning(f"Technique mswordmacro_vars failed with error: {e!s}")
            return None

    def simple_xor_function(self, text: bytes) -> bytes | None:
        """Try XORing the text with potential keys found in the text."""
        xorstrings = regex.findall(rb'(\w+\("((?:[0-9A-Fa-f][0-9A-Fa-f])+)"\s*,\s*"([^"]+)"\))', text)
        option_a: list[tuple[bytes, bytes, bytes, bytes | None]] = []
        option_b: list[tuple[bytes, bytes, bytes, bytes | None]] = []
        output = text
        for f, x, k in xorstrings:
            res = self.xor_with_key(binascii.a2b_hex(x), k)
            if self.printable_ratio(res) == 1:
                option_a.append((f, x, k, res))
            else:
                option_a.append((f, x, k, None))
            # try by shifting the key by 1
            res = self.xor_with_key(binascii.a2b_hex(x), k[1:] + k[0:1])
            if self.printable_ratio(res) == 1:
                option_b.append((f, x, k, res))
            else:
                option_b.append((f, x, k, None))

        xorstrings = []
        if None not in (y[3] for y in option_a):
            xorstrings = option_a
        elif None not in (z[3] for z in option_b):
            xorstrings = option_b

        for f, _, _, r in xorstrings:
            if r is not None:
                output = output.replace(f, b'"' + r + b'"')

        if output == text:
            return None
        return output

    @staticmethod
    def xor_with_key(s: bytes, k: bytes) -> bytes:
        """XOR s using the key k."""
        return bytes([a ^ b for a, b in zip(s, (len(s) // len(k) + 1) * k)])

    @staticmethod
    def zp_xor_with_key(s: bytes, k: bytes) -> bytes:
        """XOR variant where xoring is skipped for 0 bytes and when the byte is equal to the keybyte."""
        return bytes([a if a in (0, b) else a ^ b for a, b in zip(s, (len(s) // len(k) + 1) * k)])

    @staticmethod
    def clean_up_final_layer(text: bytes) -> bytes:
        """Remove deobfuscripter artifacts from final layer for display."""
        output = regex.sub(rb"\r", b"", text)
        return regex.sub(rb"<deobsfuscripter:[^>]+>\n?", b"", output)

    # noinspection PyBroadException
    def extract_htmlscript(self, text: bytes) -> list[bytes]:
        """Extract scripts from html."""
        objects = []
        try:
            html = BeautifulSoup(text, "lxml")
            for tag_type in ["object", "embed", "script"]:
                for s in html.find_all(tag_type):
                    objects.append(str(s).encode("utf-8"))
        except Exception as e:
            self.log.warning(f"Failure in extract_htmlscript function: {e!s}")
            objects = []
        return objects

    # --- Execute --------------------------------------------------------------------------------------------------

    def execute(self, request: ServiceRequest) -> None:
        # --- Setup ----------------------------------------------------------------------------------------------
        request.result = Result()
        md = DecoderWrapper(self.working_directory)

        max_attempts = 100 if request.deep_scan else 10

        # --- Prepare Techniques ----------------------------------------------------------------------------------
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
            # ('Octal Charcodes', self.charcode_oct),
            ("Unicode Charcodes", self.charcode_unicode),
            ("XML Charcodes", self.charcode_xml),
            ("Hex Int Constants", self.hex_constant),
        ]
        second_pass.extend(first_pass)
        final_pass: TechniqueList = []
        final_pass.extend(second_pass)

        code_extracts = [(".*html.*", "HTML scripts extraction", self.extract_htmlscript)]

        layer = request.file_contents

        # --- Stage 1: Script Extraction --------------------------------------------------------------------------
        extract_res = ResultSection("Extraction")
        for pattern, name, func in code_extracts:
            if regex.match(regex.compile(pattern), request.task.file_type):
                extracted_parts = func(request.file_contents)
                layer = b"\n".join(extracted_parts).strip()
                extract_res.add_line(name)
                break
        if len(layer.strip()) < 3:
            return  # No script present in file
        if request.file_type == "code/ps1":
            sig = regex.search(
                rb"# SIG # Begin signature block\r\n(?:# [A-Za-z0-9+/=]+\r\n)+# SIG # End signature block",
                request.file_contents,
            )
            if sig:
                layer = layer[: sig.start()] + layer[sig.end() :]
                lines = sig.group().split(b"\r\n# ")
                base64 = b"".join(line.strip() for line in lines[1:-1])
                try:
                    # Extract signature
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
        # Save extracted scripts before deobfuscation
        before_deobfuscation = layer

        # --- Stage 2: Deobsfucation ------------------------------------------------------------------------------
        seen_iocs: set[bytes] = set()
        passes: dict[int, tuple[list[str], dict[str, set[bytes]]]] = {}
        techniques = first_pass
        n_pass = 0  # Ensure n_pass is bound outside of the loop
        for n_pass in range(max_attempts):
            layer, techiques_used, iocs = self._deobfuscripter_pass(layer, techniques, md)
            if techiques_used:
                # Store the techniques used and new iocs found for each pass
                passes[n_pass] = techiques_used, filter_iocs(iocs, before_deobfuscation, seen_iocs)
            else:
                # If there are no new layers in a pass, start second pass or break
                if len(techniques) != len(first_pass):
                    # Already on second pass
                    break
                techniques = second_pass

        # --- Final Layer -----------------------------------------------------------------------------------------
        layer, final_techniques, final_iocs = self._deobfuscripter_pass(layer, final_pass, md, final=True)
        if final_techniques:
            passes[n_pass + 1] = final_techniques, filter_iocs(final_iocs, before_deobfuscation, seen_iocs)

        # Get new reversed iocs
        rev_iocs = filter_iocs(md.ioc_tags(layer[::-1]), before_deobfuscation, seen_iocs, reversed=True)

        # --- Compiling results -----------------------------------------------------------------------------------
        if request.get_param("extract_original_iocs"):
            pat_values = get_tree_tags(md.multidecoder.scan(before_deobfuscation, 1))
            ioc_res = ResultSection(
                "The following IOCs were found in the original file",
                parent=request.result,
                body_format=BODY_FORMAT.MEMORY_DUMP,
            )
            for k, val in pat_values.items():
                for v in val:
                    if ioc_res:
                        ioc_res.add_line(f"Found {k.upper().replace('.', ' ')}: {safe_str(v)}")
                        ioc_res.add_tag(k, v)

        if not passes:
            return
        # Cleanup final layer
        clean = self.clean_up_final_layer(layer)
        if clean == request.file_contents:
            return

        # Display obfuscation steps
        heuristic = Heuristic(1)
        mres = ResultSection(
            "De-obfuscation steps taken by DeobsfuScripter",
            parent=request.result,
            heuristic=heuristic,
        )

        tech_count: Counter[str] = Counter()
        for p in passes.values():
            tech_count.update(p[0])
        for tech, count in tech_count.items():
            heuristic.add_signature_id(tech, frequency=count)
            mres.add_line(f"{tech}, {count} time(s).")

        # Display final layer
        byte_count = 5000
        if request.deep_scan or (len(clean) > 1000 and heuristic.score >= 500) or seen_iocs:
            # Save extracted file
            byte_count = 500
            file_name = f"{request.sha256}_decoded_final"
            file_path = os.path.join(self.working_directory, file_name)
            # Ensure directory exists before write
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "wb+") as f:
                f.write(clean)
                self.log.debug(f"Submitted dropped file for analysis: {file_path}")
            request.add_supplementary(file_path, file_name, "Final deobfuscated layer")

        ResultSection(
            f"First {byte_count} bytes of the final layer:",
            body=safe_str(clean[:byte_count]),
            body_format=BODY_FORMAT.MEMORY_DUMP,
            parent=request.result,
        )

        # Report new IOCs
        new_ioc_res = ResultSection("New IOCs found after de-obfustcation", body_format=BODY_FORMAT.MEMORY_DUMP)
        heuristic = 0
        for n_pass, (_, iocs) in passes.items():
            if not iocs:
                continue
            new_ioc_res.add_line(f"New IOCs found in pass {n_pass}:")
            for ioc_type in iocs:
                for ioc in iocs[ioc_type]:
                    if n_pass == 0:  # iocs in the first pass can be found by other services
                        heuristic = 5
                    elif heuristic < 7:
                        heuristic = 7 if "network" in ioc_type and ioc_type != "network.static.domain" else 6
                    new_ioc_res.add_line(f"Found {ioc_type.upper().replace('.', ' ')}: {safe_str(ioc)}")
                    new_ioc_res.add_tag(ioc_type, ioc)
        if rev_iocs:
            new_ioc_res.add_line("New IOCs found reversed in the final layer:")
            for ioc_type in rev_iocs:
                for ioc in rev_iocs[ioc_type]:
                    heuristic = max(
                        7 if "network" in ioc_type and ioc_type != "network.static.domain" else 6,
                        heuristic,
                    )
                    new_ioc_res.add_line(f"Found {ioc_type.upper().replace('.', ' ')}: {safe_str(ioc)}")
                    new_ioc_res.add_tag(ioc_type, ioc)
        if heuristic > 0:
            new_ioc_res.set_heuristic(heuristic)
        if new_ioc_res.body:
            request.result.add_section(new_ioc_res)

        # Report extracted files
        if md.extracted_files:
            ext_file_res = ResultSection(
                "The following files were extracted during the deobfuscation",
                heuristic=Heuristic(8),
                parent=request.result,
            )
            for extracted in md.extracted_files:
                file_name = os.path.basename(extracted)
                try:
                    if request.add_extracted(
                        extracted,
                        file_name,
                        "File of interest deobfuscated from sample",
                        safelist_interface=self.api_interface,
                    ):
                        ext_file_res.add_line(file_name)
                except MaxExtractedExceeded:
                    self.log.warning("Extraction limit exceeded while adding files of interest.")
                    break

    @staticmethod
    def _deobfuscripter_pass(
        layer: bytes,
        techniques: TechniqueList,
        md: DecoderWrapper,
        *,
        final: object = False,
    ) -> tuple[bytes, list[str], dict[str, set[bytes]]]:
        techniques_used = []
        for name, technique in techniques:
            result = technique(layer)
            if result:
                techniques_used.append(name)
                # Looks like it worked, continue with the new layer
                layer = result
        # Use multidecoder techniques and ioc tagging
        tree = md.multidecoder.scan(layer) if final else md.multidecoder.scan(layer, 1)
        md.extract_files(tree, 500)
        obfuscations = {node.obfuscation for node in tree}
        obfuscations.discard(b"")
        techniques_used.extend(obfuscations)
        iocs = get_tree_tags(tree)  # Get IoCs for the pass
        layer = tree.flatten()
        return layer, techniques_used, iocs
