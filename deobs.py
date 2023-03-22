""" DeobfuScripter: Script Deobfuscation Service """

from __future__ import annotations

import binascii
import hashlib
import os

from collections import Counter
from functools import partial
from itertools import chain
from typing import Callable, Dict, List, Optional, Set, Tuple

import magic
import regex

from bs4 import BeautifulSoup

from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest, MaxExtractedExceeded
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic


class DeobfuScripter(ServiceBase):
    """ Service for deobfuscating scripts """
    FILETYPES = ['application', 'document', 'exec', 'image', 'Microsoft', 'text']
    VALIDCHARS = b' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    BINCHARS = bytes(list(set(range(0, 256)) - set(VALIDCHARS)))

    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)
        self.hashes: Set[str] = set()
        self.files_extracted: Set[str] = set()

    # --- Support Modules ----------------------------------------------------------------------------------------------

    def printable_ratio(self, text: bytes) -> float:
        """ Calcuate the ratio of printable characters to total characters in text """
        return float(float(len(text.translate(None, self.BINCHARS))) / float(len(text)))

    @staticmethod
    def encode_codepoint(codepoint: int) -> bytes:
        """ Returns the utf-8 encoding of a unicode codepoint """
        return chr(codepoint).encode('utf-8')

    @staticmethod
    def codepoint_sub(match: regex.Match, base: int = 16) -> bytes:
        """ Replace method for unicode codepoint regex substitutions.

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
        """ Add k to each byte of s """
        return bytes([(c + k) & 0xff for c in s])

    @staticmethod
    def charcode(text: bytes) -> Optional[bytes]:
        """ Replace character codes with the corresponding characters """
        # To do: what decimal encodings exist in scripting languages and how to decode them?

    @staticmethod
    def charcode_hex(text: bytes) -> Optional[bytes]:
        """ Replace hex character codes with the corresponding characters """
        output = regex.sub(rb'(?i)(?:\\x|0x|%)([a-f0-9]{2})', lambda m: binascii.unhexlify(m.group(1)), text)
        return output if output != text else None

    @staticmethod
    def charcode_unicode(text: bytes) -> Optional[bytes]:
        """ Replace unicode character codes with the corresponding utf-8 byte sequence"""
        output = regex.sub(rb'(?i)(?:\\u|%u)([a-f0-9]{4})', DeobfuScripter.codepoint_sub, text)
        return output if output != text else None

    @staticmethod
    def charcode_xml(text: bytes) -> Optional[bytes]:
        """ Replace XML escape sequences with the corresponding character """
        output = regex.sub(rb'(?i)&#x([a-z0-9]{1,6});', DeobfuScripter.codepoint_sub, text)
        output = regex.sub(rb'&#([0-9]{1,7});', partial(DeobfuScripter.codepoint_sub, base=10), output)
        return output if output != text else None

    @staticmethod
    def chr_decode(text: bytes) -> Optional[bytes]:
        """ Replace calls to chr with the corresponding character """
        output = text
        for fullc, c in regex.findall(rb'(chr[bw]?\(([0-9]{1,3})\))', output, regex.I):
            # noinspection PyBroadException
            try:
                output = regex.sub(regex.escape(fullc), f'"{chr(int(c))}"'.encode('utf-8'), output)
            except Exception:
                continue
        if output == text:
            return None
        return output

    @staticmethod
    def string_replace(text: bytes) -> Optional[bytes]:
        """ Replace calls to replace() with their output """
        if b'replace(' in text.lower():
            # Process string with replace functions calls
            # Such as "SaokzueofpigxoFile".replace(/ofpigx/g, "T").replace(/okzu/g, "v")
            output = text
            # Find all occurrences of string replace (JS)
            for strreplace in [o[0] for o in
                               regex.findall(rb'(["\'][^"\']+["\']((\.replace\([^)]+\))+))', output, flags=regex.I)]:
                substitute = strreplace
                # Extract all substitutions
                for str1, str2 in regex.findall(rb'\.replace\([/\'"]([^,]+)[/\'\"]g?\s*,\s*[\'\"]([^)]*)[\'\"]\)',
                                                substitute, flags=regex.I):
                    # Execute the substitution
                    substitute = substitute.replace(str1, str2)
                # Remove the replace calls from the layer (prevent accidental substitutions in the next step)
                if b'.replace(' in substitute.lower():
                    substitute = substitute[:substitute.lower().index(b'.replace(')]
                output = output.replace(strreplace, substitute)

            # Process global string replace
            replacements = regex.findall(rb'replace\(\s*/([^)]+)/g?, [\'"]([^\'"]*)[\'"]', output)
            for str1, str2 in replacements:
                output = output.replace(str1, str2)
            # Process VB string replace
            replacements = regex.findall(rb'Replace\(\s*["\']?([^,"\']*)["\']?\s*,\s*["\']?'
                                         rb'([^,"\']*)["\']?\s*,\s*["\']?([^,"\']*)["\']?', output)
            for str1, str2, str3 in replacements:
                output = output.replace(str1, str1.replace(str2, str3))
            output = regex.sub(rb'\.replace\(\s*/([^)]+)/g?, [\'"]([^\'"]*)[\'"]\)', b'', output)
            if output != text:
                return output
        return None

    def b64decode_str(self, text: bytes) -> Optional[bytes]:
        """ Decode base64 """
        b64str: list[bytes] = regex.findall(b'((?:[A-Za-z0-9+/]{3,}={0,2}(?:&#[x1][A0];)?[\r]?[\n]?){6,})', text)
        output = text
        for bmatch in b64str:
            s = (bmatch.replace(b'\n', b'')
                       .replace(b'\r', b'')
                       .replace(b' ', b'')
                       .replace(b'&#xA;', b'')
                       .replace(b'&#10;', b''))
            uniq_char = set(s)
            if len(uniq_char) <= 6 or len(s) < 16 or len(s) % 4:
                continue
            try:
                d = binascii.a2b_base64(s)
            except binascii.Error:
                continue
            sha256hash = hashlib.sha256(d).hexdigest()
            if sha256hash not in self.hashes:
                if len(d) > 500:
                    m = magic.Magic(mime=True)
                    mag = magic.Magic()
                    ftype = m.from_buffer(d)
                    mag_ftype = mag.from_buffer(d)
                    for file_type in self.FILETYPES:
                        if (file_type in ftype and 'octet-stream' not in ftype) or file_type in mag_ftype:
                            b64_file_name = f"{sha256hash[0:10]}_b64_decoded"
                            b64_file_path = os.path.join(self.working_directory, b64_file_name)
                            with open(b64_file_path, 'wb') as b64_file:
                                b64_file.write(d)
                            self.files_extracted.add(b64_file_path)
                            self.hashes.add(sha256hash)
                            break

                if len(set(d)) > 6 and all(8 < c < 127 for c in d) and len(regex.sub(rb"\s", b"", d)) > 14:
                    output = output.replace(bmatch, d)
                else:
                    # Test for ASCII seperated by \x00
                    p = d.replace(b'\x00', b'')
                    if len(set(p)) > 6 and all(8 < c < 127 for c in p) and len(regex.sub(rb"\s", b"", p)) > 14:
                        output = output.replace(bmatch, p)

        if output == text:
            return None
        return output

    @staticmethod
    def vars_of_fake_arrays(text: bytes) -> Optional[bytes]:
        """ Parse variables of fake arrays """
        replacements = regex.findall(rb'var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\[(\d+)\]', text)
        if len(replacements) > 0:
            #    ,- Make sure we do not process these again
            output = regex.sub(rb'var\s+([^=]+)\s*=', rb'XXX \1 =', text)
            for varname, array, pos in replacements:
                try:
                    value = regex.split(rb'\s*,\s*', array)[int(pos)]
                except IndexError:
                    # print '[' + array + '][' + pos + ']'
                    break
                output = output.replace(varname, value)
            if output != text:
                return output
        return None

    def array_of_strings(self, text: bytes) -> Optional[bytes]:
        """ Replace arrays of strings with the combined string """
        # noinspection PyBroadException
        try:
            replacements = regex.findall(rb'var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\s*;', text)
            if len(replacements) > 0:
                #    ,- Make sure we do not process these again
                output = text
                for varname, values in replacements:
                    occurences = [int(x) for x in regex.findall(varname + rb'\s*\[(\d+)\]', output)]
                    for i in occurences:
                        try:
                            output = regex.sub(varname + rb'\s*\[(%d)\]' % i,
                                               values.split(b',')[i].replace(b'\\', b'\\\\'), output)
                        except IndexError:
                            # print '[' + array + '][' + pos + ']'
                            break
                if output != text:
                    return output
        except Exception as e:
            self.log.warning(f"Technique array_of_strings failed with error: {str(e)}")

        return None

    @staticmethod
    def concat_strings(text: bytes) -> Optional[bytes]:
        """ Concatenate disconnected strings """
        # Line continuation character in VB -- '_'
        output = regex.sub(rb'[\'"][\s\n_]*?[+&][\s\n_]*[\'"]', b'', text)
        if output != text:
            return output
        return None

    @staticmethod
    def str_reverse(text: bytes) -> Optional[bytes]:
        """ Replace StrReverse function calls with the reverse of its argument """
        output = text
        # VBA format StrReverse("[text]")
        replacements = regex.findall(rb'(StrReverse\("(.+?(?="\))))', output)
        for full, string in replacements:
            reversed_string = full.replace(string, string[::-1]).replace(b"StrReverse(", b"")[:-1]
            output = output.replace(full, reversed_string)
        if output != text:
            return output
        return None

    @staticmethod
    def powershell_vars(text: bytes) -> Optional[bytes]:
        """ Replace PowerShell variables with their values """
        replacements_string = regex.findall(rb'(\$(?:\w+|{[^\}]+\}))\s*=[^=]\s*[\"\']([^\"\']+)[\"\']', text)
        replacements_func = regex.findall(rb'(\$(?:\w+|{[^\}]+\}))\s*=\s*([^=\"\'\s$]{3,50})[\s]', text)
        if len(replacements_string) > 0 or len(replacements_func) > 0:
            #    ,- Make sure we do not process these again
            output = regex.sub(rb'\$((?:\w+|{[^\}]+\}))\s*=', rb'\$--\1 =', text)
            for varname, string in replacements_string:
                output = output.replace(varname, string)
            for varname, string in replacements_func:
                output = output.replace(varname, string)
            if output != text:
                return output

        return None

    @staticmethod
    def powershell_carets(text: bytes) -> Optional[bytes]:
        """ Remove PowerShell carets """
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
    def msoffice_embedded_script_string(self, text: bytes) -> Optional[bytes]:
        """ Replace variables with their values in MSOffice embedded scripts """
        try:
            scripts: Dict[bytes, List[bytes]] = {}
            output = text
            # bad, prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = regex.findall(
                rb'^(\s*(\w+)\s*=\s*\w*\s*\+?\s(["\'])(.+)["\']\s*\+\s*vbCrLf\s*$)', output, regex.M)
            if len(replacements) > 0:
                for full, variable_name, delim, value in replacements:
                    scripts.setdefault(variable_name, [])
                    scripts[variable_name].append(value.replace(delim + delim, delim))
                    output = output.replace(full, b'<deobsfuscripter:msoffice_embedded_script_string_var_assignment>')

            for script_var, script_lines in scripts.items():
                new_script_name = b'new_script__' + script_var
                output = regex.sub(rb'(.+)\b' + script_var + rb'\b', b'\\1' + new_script_name, output)
                output += b"\n\n\n' ---- script referenced by \"" + new_script_name + b"\" ----\n\n\n"
                output += b"\n".join(script_lines)

            if output == text:
                return None
            return output

        except Exception as e:
            self.log.warning(f"Technique msoffice_embedded_script_string failed with error: {str(e)}")
            return None

    def mswordmacro_vars(self, text: bytes) -> Optional[bytes]:
        """ Replaces Microsoft Word variables with their values """
        # noinspection PyBroadException
        try:
            output = text
            # prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = regex.findall(rb'^\s*((?:Const[\s]*)?(\w+)\s*='
                                         rb'\s*((?:["][^"]+["]|[\'][^\']+[\']|[0-9]*)))[\s\r]*$',
                                         output, regex.MULTILINE | regex.DOTALL)
            if len(replacements) > 0:
                # If one variable is defined more then once take the second definition
                replacements = [(v[0], k, v[1]) for k, v in {i[1]: (i[0], i[2]) for i in replacements}.items()]
                for full, varname, value in replacements:
                    if len(regex.findall(rb'\b' + varname + rb'\b', output)) == 1:
                        # If there is only one instance of these, it's probably noise.
                        output = output.replace(full, b'<deobsfuscripter:mswordmacro_unused_variable_assignment>')
                    else:
                        final_val = value.replace(b'"', b"")
                        # Stacked strings
                        # b = "he"
                        # b = b & "llo "
                        # b = b & "world!"
                        stacked = regex.findall(rb'^\s*(' + varname + rb'\s*=\s*'
                                                + varname + rb'\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\'])))[\s\r]*$',
                                                output, regex.MULTILINE | regex.DOTALL)
                        if len(stacked) > 0:
                            for sfull, val in stacked:
                                final_val += val.replace(b'"', b"")
                                output = output.replace(sfull, b'<deobsfuscripter:mswordmacro_var_assignment>')
                        output = output.replace(full, b'<deobsfuscripter:mswordmacro_var_assignment>')
                        # If more than a of the variable name left, the assumption is that this did not
                        # work according to plan, so just replace a few for now.
                        output = regex.sub(rb'(\b' + regex.escape(varname) +
                                           rb'(?!\s*(?:=|[+&]\s*' + regex.escape(varname) + rb'))\b)',
                                           b'"' + final_val.replace(b"\\", b"\\\\") + b'"',
                                           output, count=5)
                        # output = regex.sub(rb'(.*[^\s].*)\b' + varname + rb'\b',
                        #                 b'\\1"' + final_val.replace(b"\\", b"\\\\") + b'"',
                        #                 output)

            # Remaining stacked strings
            replacements = regex.findall(rb'^\s*((\w+)\s*=\s*(\w+)\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\'])))[\s\r]*$',
                                         output, regex.MULTILINE | regex.DOTALL)
            replacements_vars = {x[1] for x in replacements}
            for v in replacements_vars:
                final_val = b""
                for full, varname, _, value in replacements:
                    if varname != v:
                        continue
                    final_val += value.replace(b'"', b"")
                    output = output.replace(full, b'<deobsfuscripter:mswordmacro_var_assignment>')
                output = regex.sub(rb'(\b' + v +
                                   rb'(?!\s*(?:=|[+&]\s*' + v + rb'))\b)',
                                   b'"' + final_val.replace(b"\\", b"\\\\") + b'"',
                                   output, count=5)

            if output == text:
                return None
            return output

        except Exception as e:
            self.log.warning(f"Technique mswordmacro_vars failed with error: {str(e)}")
            return None

    def simple_xor_function(self, text: bytes) -> Optional[bytes]:
        """ Tries XORing the text with potential keys found in the text """
        xorstrings = regex.findall(rb'(\w+\("((?:[0-9A-Fa-f][0-9A-Fa-f])+)"\s*,\s*"([^"]+)"\))', text)
        option_a: List[Tuple[bytes, bytes, bytes, Optional[bytes]]] = []
        option_b: List[Tuple[bytes, bytes, bytes, Optional[bytes]]] = []
        output = text
        for f, x, k in xorstrings:
            res = self.xor_with_key(binascii.a2b_hex(x), k)
            if self.printable_ratio(res) == 1:
                option_a.append((f, x, k, res))
                # print 'A:',f,x,k, res
            else:
                option_a.append((f, x, k, None))
            # try by shifting the key by 1
            res = self.xor_with_key(binascii.a2b_hex(x), k[1:] + k[0:1])
            if self.printable_ratio(res) == 1:
                option_b.append((f, x, k, res))
                # print 'B:',f,x,k, res
            else:
                option_b.append((f, x, k, None))

        xorstrings = []
        if None not in map(lambda y: y[3], option_a):
            xorstrings = option_a
        elif None not in map(lambda z: z[3], option_b):
            xorstrings = option_b

        for f, x, k, r in xorstrings:
            if r is not None:
                output = output.replace(f, b'"' + r + b'"')

        if output == text:
            return None
        return output

    @staticmethod
    def xor_with_key(s: bytes, k: bytes) -> bytes:
        """ XOR s using the key k """
        return bytes([a ^ b for a, b in zip(s, (len(s) // len(k) + 1) * k)])

    @staticmethod
    def zp_xor_with_key(s: bytes, k: bytes) -> bytes:
        """ XOR variant where xoring is skipped for 0 bytes and when the byte is equal to the keybyte """
        return bytes([a if a in (0, b) else a ^ b for a, b in zip(s, (len(s) // len(k) + 1) * k)])

    @staticmethod
    def clean_up_final_layer(text: bytes) -> bytes:
        """ Remove deobfuscripter artifacts from final layer for display """
        output = regex.sub(rb'\r', b'', text)
        output = regex.sub(rb'<deobsfuscripter:[^>]+>\n?', b'', output)
        return output

    # noinspection PyBroadException
    def extract_htmlscript(self, text: bytes) -> List[bytes]:
        """ Extract scripts from html """
        objects = []
        try:
            html = BeautifulSoup(text, 'lxml')
            for tag_type in ['object', 'embed', 'script']:
                for s in html.find_all(tag_type):
                    objects.append(str(s).encode('utf-8'))
        except Exception as e:
            self.log.warning(f"Failure in extract_htmlscript function: {str(e)}")
            objects = []
        return objects

    # --- Execute --------------------------------------------------------------------------------------------------

    def execute(self, request: ServiceRequest) -> None:
        # --- Setup ----------------------------------------------------------------------------------------------
        request.result = Result()
        patterns = PatternMatch()

        max_attempts = 100 if request.deep_scan else 10

        self.files_extracted = set()
        self.hashes = set()

        # --- Prepare Techniques ----------------------------------------------------------------------------------
        TechniqueList = List[Tuple[str, Callable[[bytes], Optional[bytes]]]]
        first_pass: TechniqueList = [
            ('MSOffice Embedded script', self.msoffice_embedded_script_string),
            ('CHR and CHRB decode', self.chr_decode),
            ('String replace', self.string_replace),
            ('Powershell carets', self.powershell_carets),
            ('Array of strings', self.array_of_strings),
            ('Fake array vars', self.vars_of_fake_arrays),
            ('Reverse strings', self.str_reverse),
            ('B64 Decode', self.b64decode_str),
            ('Simple XOR function', self.simple_xor_function),
        ]
        second_pass: TechniqueList = [
            ('Concat strings', self.concat_strings),
            ('MSWord macro vars', self.mswordmacro_vars),
            ('Powershell vars', self.powershell_vars),
            ('Hex Charcodes', self.charcode_hex),
            ('Unicode Charcodes', self.charcode_unicode),
            ('XML Charcodes', self.charcode_xml)
        ]
        second_pass.extend(first_pass)
        final_pass: TechniqueList = []

        code_extracts = [
            ('.*html.*', "HTML scripts extraction", self.extract_htmlscript)
        ]

        layers_list: list[str] = []
        layer = request.file_contents

        # --- Stage 1: Script Extraction --------------------------------------------------------------------------
        if request.file_type == 'code/ps1':
            sig = regex.search(
                rb'# SIG # Begin signature block\r\n(?:# [A-Za-z0-9+/=]+\r\n)+# SIG # End signature block',
                request.file_contents)
            if sig:
                layer = layer[:sig.start()] + layer[sig.end():]
                lines = sig.group().split(b'\r\n# ')
                base64 = b''.join(line.strip() for line in lines[1:-1])
                try:
                    # Extract signature
                    signature = binascii.a2b_base64(base64)
                    sig_filename = 'powershell_signature'
                    sig_path = os.path.join(self.working_directory, sig_filename)
                    with open(sig_path, 'wb+') as f:
                        f.write(signature)
                    request.add_extracted(sig_path, sig_filename, "Powershell Signature")
                except binascii.Error:
                    pass
        for pattern, name, func in code_extracts:
            if regex.match(regex.compile(pattern), request.task.file_type):
                extracted_parts = func(request.file_contents)
                layer = b"\n".join(extracted_parts).strip()
                layers_list.append(name)
                break
        if len(layer.strip()) < 3:
            # Exit immediately if no script is found
            return
        # Save extracted scripts before deobfuscation
        before_deobfuscation = layer

        # --- Stage 2: Deobsfucation ------------------------------------------------------------------------------
        techniques = first_pass
        layers_count = len(layers_list)
        for _ in range(max_attempts):
            for name, technique in techniques:
                result = technique(layer)
                if result:
                    layers_list.append(name)
                    # Looks like it worked, restart with new layer
                    layer = result
            # If there are no new layers in a pass, start second pass or break
            if layers_count == len(layers_list):
                if len(techniques) != len(first_pass):
                    # Already on second pass
                    break
                techniques = second_pass
            layers_count = len(layers_list)

        # --- Final Layer -----------------------------------------------------------------------------------------
        final_pass.extend(techniques)
        for name, technique in final_pass:
            res = technique(layer)
            if res:
                layers_list.append(name)
                layer = res

        # --- Compiling results -----------------------------------------------------------------------------------
        if request.get_param('extract_original_iocs'):
            pat_values = patterns.ioc_match(before_deobfuscation, bogon_ip=True, just_network=False)
            ioc_res = ResultSection("The following IOCs were found in the original file", parent=request.result,
                                    body_format=BODY_FORMAT.MEMORY_DUMP)
            for k, val in pat_values.items():
                for v in val:
                    if ioc_res:
                        ioc_res.add_line(f"Found {k.upper().replace('.', ' ')}: {safe_str(v)}")
                        ioc_res.add_tag(k, v)

        if not layers_list:
            return
        # Cleanup final layer
        clean = self.clean_up_final_layer(layer)
        if clean == request.file_contents:
            return

        # Display obfuscation steps
        heuristic = Heuristic(1)
        mres = ResultSection("De-obfuscation steps taken by DeobsfuScripter",
                             parent=request.result,
                             heuristic=heuristic)

        tech_count = Counter(layers_list)
        for tech, count in tech_count.items():
            heuristic.add_signature_id(tech, frequency=count)
            mres.add_line(f"{tech}, {count} time(s).")

        # Check for new IOCs
        pat_values = patterns.ioc_match(clean, bogon_ip=True, just_network=False)
        diff_tags: Dict[str, List[bytes]] = {}
        for ioc_type, iocs in pat_values.items():
            for ioc in iocs:
                if ioc_type == 'network.static.uri':
                    if b'/'.join(ioc.split(b'/', 3)[:3]) not in before_deobfuscation:
                        diff_tags.setdefault(ioc_type, [])
                        diff_tags[ioc_type].append(ioc)
                elif ioc not in before_deobfuscation:
                    diff_tags.setdefault(ioc_type, [])
                    diff_tags[ioc_type].append(ioc)

        # And for new reversed IOCs
        rev_values = patterns.ioc_match(clean[::-1], bogon_ip=True, just_network=False)
        rev_tags: Dict[str, List[bytes]] = {}
        reversed_file = before_deobfuscation[::-1]
        for ioc_type, iocs in rev_values.items():
            for ioc in iocs:
                if ioc_type == 'network.static.uri':
                    if b'/'.join(ioc.split(b'/', 3)[:3]) not in reversed_file:
                        rev_tags.setdefault(ioc_type, [])
                        rev_tags[ioc_type].append(ioc)
                elif ioc not in reversed_file and ioc[::-1] not in diff_tags.get(ioc_type, []):
                    rev_tags.setdefault(ioc_type, [])
                    rev_tags[ioc_type].append(ioc)

        # Display final layer
        byte_count = 5000
        if request.deep_scan or (len(clean) > 1000 and heuristic.score >= 500) or diff_tags or rev_tags:
            # Save extracted file
            byte_count = 500
            file_name = f"{os.path.basename(request.file_name)}_decoded_final"
            file_path = os.path.join(self.working_directory, file_name)
            # Ensure directory exists before write
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'wb+') as f:
                f.write(clean)
                self.log.debug(f"Submitted dropped file for analysis: {file_path}")
            request.add_extracted(file_path, file_name, "Final deobfuscation layer")

        ResultSection(f"First {byte_count} bytes of the final layer:", body=safe_str(clean[:byte_count]),
                      body_format=BODY_FORMAT.MEMORY_DUMP, parent=request.result)

        # Display new IOCs from final layer
        if diff_tags or rev_tags:
            ioc_new = ResultSection("New IOCs found after de-obfustcation", parent=request.result,
                                    body_format=BODY_FORMAT.MEMORY_DUMP)
            has_network_heur = False
            for ty, val in chain(diff_tags.items(), rev_tags.items()):
                if "network" in ty and ty != 'network.static.domain':
                    has_network_heur = True
                for v in val:
                    ioc_new.add_line(f"Found {ty.upper().replace('.', ' ')}: {safe_str(v)}")
                    ioc_new.add_tag(ty, v)

            if has_network_heur:
                ioc_new.set_heuristic(7)
            else:
                ioc_new.set_heuristic(6)

        if len(self.files_extracted) > 0:
            ext_file_res = ResultSection("The following files were extracted during the deobfuscation",
                                         heuristic=Heuristic(8), parent=request.result)
            for extracted in self.files_extracted:
                file_name = os.path.basename(extracted)
                try:
                    if request.add_extracted(extracted, file_name, "File of interest deobfuscated from sample",
                                             safelist_interface=self.api_interface):
                        ext_file_res.add_line(file_name)
                except MaxExtractedExceeded:
                    self.log.warning('Extraction limit exceeded while adding files of interest.')
                    break
